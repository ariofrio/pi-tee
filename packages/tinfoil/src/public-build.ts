import { createHash, randomBytes } from "node:crypto";
import { isNetworkFailure, readBoundedBody, TeeError, upstreamFailure } from "pi-tee-core";
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { computeBootMeasurements } from "./boot-measurements.js";
import { computeSnpLaunchDigest } from "./snp-measurement.js";
import { PUBLIC_BUILD_HELPER_DIGEST, runPublicBuildHelper } from "./wasm-verifiers.js";

const parseJson = (bytes: string | Uint8Array): any => JSON.parse(typeof bytes === "string" ? bytes : new TextDecoder("utf-8", { fatal: true }).decode(bytes));
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

// Process-local, bounded cache: no persistent evidence, credentials or keys.
// Fresh CPU/GPU/freshness appraisal is never cached. Helper artifacts namespace
// deterministic results so another executable cannot populate their cache.
class ArtifactCache {
  private objects = new Map<string, Buffer>();
  private bytes = 0;
  get(key: string, maxBytes: number) {
    const value = this.objects.get(key);
    if (!value || value.length > maxBytes) return undefined;
    this.objects.delete(key); this.objects.set(key, value);
    return value;
  }
  put(key: string, bytes: Buffer) {
    const old = this.objects.get(key);
    if (old) this.bytes -= old.length;
    this.objects.delete(key); this.objects.set(key, bytes); this.bytes += bytes.length;
    while (this.objects.size > 128 || this.bytes > 96 * 1024 * 1024) {
      const first = this.objects.entries().next().value!;
      this.objects.delete(first[0]); this.bytes -= first[1].length;
    }
  }
  clear() { this.objects.clear(); this.bytes = 0; }
}
const artifactCaches = new WeakMap<typeof globalThis.fetch, Map<string, ArtifactCache>>();
function cacheFor(fetch: typeof globalThis.fetch, helperDigest: string) {
  let byHelper = artifactCaches.get(fetch);
  if (!byHelper) { byHelper = new Map(); artifactCaches.set(fetch, byHelper); }
  let cache = byHelper.get(helperDigest);
  if (!cache) { cache = new ArtifactCache(); byHelper.clear(); byHelper.set(helperDigest, cache); }
  return cache;
}

// GitHub's API allows 60 unauthenticated requests per hour per address, and
// each Pi process starts with an empty in-memory cache. The two immutable
// API lookups (guest-build attestations by manifest digest, a release
// commit's parents) are persisted locally once their own check passes: a
// guest build verified from the attestation list, the parent matched against
// the build provenance. A stored lookup whose check fails is removed.
function defaultPersistentCacheDir() {
  const xdg = process.env.XDG_CACHE_HOME;
  return join(xdg && isAbsolute(xdg) ? xdg : join(homedir(), ".cache"), "pi-tee", "github-metadata");
}

// Use the cache only if it is a real directory owned by this user with no
// group or other access, so another local account cannot plant or redirect it.
async function privateDirectory(dir: string): Promise<boolean> {
  const info = await lstat(dir).catch(() => undefined);
  return !!info && info.isDirectory() && (info.mode & 0o077) === 0 && (typeof process.getuid !== "function" || info.uid === process.getuid());
}
const persistable = (url: string) => url.startsWith("https://api.github.com/");

// Artifact authentication only. Callers must independently appraise the CPU-bound
// GPU bytes and qualify runtime/key/channel behavior before production admission.
export async function verifyPublicBuildArtifacts(options: {
  raw: string; nonce: string; signal: AbortSignal; repo: string; evidenceFetch?: typeof globalThis.fetch;
  /** Defaults to the user cache directory for production delivery; off for injected fetches unless given. */
  persistentCacheDir?: string;
  allowOutdated?: boolean;
  /** Authenticates the model router's release and CPU only; it serves no model. */
  role?: "router";
}) {
  const { raw, nonce, signal, repo } = options;
  const mode = options.role === "router" ? ["--router"] : [];
  const evidenceFetch = options.evidenceFetch ?? globalThis.fetch;
  const persistentDir = options.persistentCacheDir ?? (options.evidenceFetch ? undefined : defaultPersistentCacheDir());
  // Per lookup URL: bytes read from disk, or fetched and awaiting their check.
  const persistedReads = new Set<string>();
  const pendingWrites = new Map<string, Buffer>();
  const persistentPath = (url: string) => persistentDir && join(persistentDir, sha256(Buffer.from(url)));
  // Persist a lookup once its own check passed; drop a stored one whose check failed.
  async function checked<T>(url: string, check: () => Promise<T> | T): Promise<T> {
    let result: T;
    try { result = await check(); }
    catch (error) {
      const path = persistedReads.has(url) && persistentPath(url);
      if (path) await rm(path, { force: true }).catch(() => {});
      throw error;
    }
    const bytes = pendingWrites.get(url);
    if (persistentDir && bytes) await persistMetadata(persistentDir, new Map([[persistentPath(url)!, bytes]]));
    return result;
  }
  let cache: ArtifactCache | undefined;
  async function get(url: string, redirect: RequestRedirect = "error", maxBytes = 2 * 1024 * 1024, headers: Record<string, string> = {}, expectedDigest?: string, immutable = false, missingRejects = false): Promise<Buffer> {
    signal.throwIfAborted();
    const key = expectedDigest ? `sha256:${expectedDigest}` : immutable ? `immutable:${url}` : undefined;
    const hit = key && cache?.get(key, maxBytes);
    if (hit) {
      if (expectedDigest) assert.equal(sha256(hit), expectedDigest);
      return hit;
    }
    const path = immutable && persistable(url) ? persistentPath(url) : undefined;
    if (path && await privateDirectory(persistentDir!)) {
      const stored = await readFile(path).catch(() => undefined);
      if (stored && stored.length <= maxBytes) {
        persistedReads.add(url);
        if (key) cache?.put(key, stored);
        return stored;
      }
    }
    // Content checks authenticate every byte, so transient delivery failures
    // can be retried without widening what is accepted.
    const unavailable = (status?: number) => status !== undefined ? upstreamFailure("TEE_PUBLIC_ARTIFACT_UNAVAILABLE", status, "evidence") : new TeeError("TEE_PUBLIC_ARTIFACT_UNAVAILABLE");
    const request = () => evidenceFetch(url, { signal, redirect, headers }).catch(error => {
      signal.throwIfAborted();
      throw error instanceof TeeError ? error : isNetworkFailure(error) ? upstreamFailure("TEE_PUBLIC_ARTIFACT_UNAVAILABLE") : unavailable();
    });
    let response = await request();
    for (let attempt = 0; attempt < 2 && [502, 503, 504].includes(response.status); attempt++) {
      await response.body?.cancel();
      await delay(500 * 2 ** attempt, undefined, { signal });
      response = await request();
    }
    if (!response.ok || !response.body) {
      await response.body?.cancel();
      // A content-addressed lookup that finds nothing rejects those bytes.
      throw missingRejects && response.status === 404 ? new TeeError("TEE_CVM_BUILD_REJECTED") : unavailable(response.ok ? undefined : response.status);
    }
    const bytes = Buffer.from(await readBoundedBody(response.body, maxBytes, signal));
    if (expectedDigest) assert.equal(sha256(bytes), expectedDigest);
    if (key) cache?.put(key, bytes);
    if (path) pendingWrites.set(url, bytes);
    return bytes;
  }
  let input = `{"nonce":${JSON.stringify(nonce)},"allowOutdated":${options.allowOutdated ?? false},"envelope":${raw}}`;
  async function appraise(input: string, args: string[] = []): Promise<any> {
    signal.throwIfAborted();
    const key = args.length === 1 && ["--cvm-build", "--runtime-config", "--container-reference", "--container-build"].includes(args[0]!) ? `helper:${args[0]}:${sha256(Buffer.from(input))}` : undefined;
    const hit = key && cache?.get(key, 16384);
    if (hit) return parseJson(hit);
    const result = await runPublicBuildHelper(input, args, signal);
    if (result.code !== 0) throw new TeeError("TEE_PUBLIC_BUILD_REJECTED");
    const value = parseJson(result.stdout);
    if (key) cache?.put(key, Buffer.from(result.stdout));
    return value;
  }
  try {
    signal.throwIfAborted();
    cache = cacheFor(evidenceFetch, PUBLIC_BUILD_HELPER_DIGEST);
    let verified;
    const first = await runPublicBuildHelper(input, mode, signal);
    if (first.code === 0) verified = parseJson(first.stdout);
    else if (parseJson(first.stdout).failure === "TEE_PLATFORM_CLASSIC_REQUIRED") {
      // The helper authenticated the exact v2 release identity. Delivery of its
      // classic companion is untrusted; each candidate still passes the helper.
      const references = parseJson(raw).collateral.filter((item: any) => item.format === "https://tinfoil.sh/collateral/sigstore-platform/v1");
      assert(references.length === 1);
      const reference = references[0].data;
      assert(reference.repo === "tinfoilsh/cvmimage" && /^platform-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(reference.tag));
      const classic = await get(`https://github.com/tinfoilsh/cvmimage/releases/download/${reference.tag}/platform-endorsements-classic.json`, "follow");
      const digest = sha256(classic);
      const url = `https://api.github.com/repos/tinfoilsh/cvmimage/attestations/sha256:${digest}?per_page=100`;
      const candidates = parseJson(await get(url, "error"));
      assert(Array.isArray(candidates.attestations) && candidates.attestations.length <= 100);
      for (const candidate of candidates.attestations) {
        const candidateInput = JSON.stringify({ nonce, allowOutdated: options.allowOutdated ?? false, envelope: parseJson(raw), platformClassic: { digest, bundle: candidate.bundle } });
        const result = await runPublicBuildHelper(candidateInput, mode, signal);
        if (result.code !== 0) continue;
        input = candidateInput;
        verified = parseJson(result.stdout);
        break;
      }
      assert(verified, "TEE_PLATFORM_REFERENCE_REJECTED");
    } else throw new TeeError("TEE_PUBLIC_BUILD_REJECTED");
    assert(verified.cpuVerified === true && verified.publicBuildVerified === true && verified.inferenceQualified === false, "TEE_PUBLIC_BUILD_REJECTED");
    assert.equal(verified.repo, repo);
    assert(/^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(verified.tag));
    assert(/^[a-f0-9]{40}$/.test(verified.commit));
    assert(/^[a-f0-9]{64}$/.test(verified.digest));
    assert(/^[a-f0-9]{64}$/.test(verified.codeStatementDigest));
    if (options.role === "router") return verified;

    // GitHub's public asset redirects carry no credentials. The authenticated
    // subject digest, rather than HTTPS or the release filename, authenticates bytes.
    const artifact = await get(`https://github.com/${repo}/releases/download/${verified.tag}/tinfoil-deployment.json`, "follow", 2 * 1024 * 1024, {}, verified.digest);
    assert.equal(sha256(artifact), verified.digest, "TEE_PUBLIC_ARTIFACT_DIGEST_REJECTED");
    const deployment = parseJson(artifact);
    const source = await get(`https://raw.githubusercontent.com/${repo}/${verified.commit}/tinfoil-config.yml`, "error", 2 * 1024 * 1024, {}, sha256(Buffer.from(deployment.config, "base64")));
    assert(Buffer.from(deployment.config, "base64").equals(source), "TEE_PUBLIC_SOURCE_CONFIG_REJECTED");
    assert(deployment.cmdline.split(" ").includes(`tinfoil-config-hash=${sha256(source)}`), "TEE_PUBLIC_SOURCE_CONFIG_REJECTED");
    assert(deployment.hashes && /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(deployment.hashes.version), "TEE_CVM_BUILD_REJECTED");
    const cvmTag = deployment.hashes.version;
    const manifestName = `tinfoil-inference-${cvmTag}-manifest.json`;
    const manifest = await get(`https://images.tinfoil.sh/cvm/${manifestName}`, "error", 2 * 1024 * 1024, {}, undefined, true);
    // Public delivery can substitute or withhold bundles. Only the local verifier
    // can authorize the exact release workflow, source commit and artifact bytes.
    // This bounded page is a candidate set, not an assertion that every attestation
    // was examined. No matching candidate means failure, never unchecked acceptance.
    const attestationsUrl = `https://api.github.com/repos/tinfoilsh/cvmimage/attestations/sha256:${sha256(manifest)}?per_page=100`;
    const cvmAttestationList = await get(attestationsUrl, "error", 2 * 1024 * 1024, {}, undefined, true, true);
    const cvm = await checked(attestationsUrl, async () => {
      const candidates = parseJson(cvmAttestationList);
      assert(Array.isArray(candidates.attestations) && candidates.attestations.length <= 100, "TEE_CVM_BUILD_REJECTED");
      let cvm;
      for (const candidate of candidates.attestations) {
        try {
          cvm = await appraise(JSON.stringify({ tag: cvmTag, manifest: manifest.toString("base64"), bundle: candidate.bundle }), ["--cvm-build"]);
          break;
        } catch { /* Untrusted discovery may include unrelated build identities. */ }
      }
      assert(cvm?.cvmBuildVerified === true && cvm.inferenceQualified === false && cvm.repo === "tinfoilsh/cvmimage" && cvm.workflow === "release.yml", "TEE_CVM_BUILD_REJECTED");
      assert(/^[a-f0-9]{40}$/.test(cvm.commit), "TEE_CVM_BUILD_REJECTED");
      return cvm;
    });
    for (const name of ["version", "root", "initrd", "kernel", "raw"]) {
      assert.equal(deployment.hashes[name], cvm.hashes[name], "TEE_CVM_MANIFEST_MISMATCH");
    }
    const expectedCommand = `readonly=on pci=realloc,nocrs modprobe.blacklist=nouveau nouveau.modeset=0 root=/dev/mapper/root roothash=${cvm.hashes.root} tinfoil-config-hash=${sha256(source)}`;
    assert.equal(deployment.cmdline, expectedCommand, "TEE_PUBLIC_BOOT_COMMAND_REJECTED");
    const [kernel, initrd] = await Promise.all([
      get(`https://images.tinfoil.sh/cvm/tinfoil-inference-${cvmTag}.vmlinuz`, "error", 32 * 1024 * 1024, {}, cvm.hashes.kernel),
      get(`https://images.tinfoil.sh/cvm/tinfoil-inference-${cvmTag}.initrd`, "error", 32 * 1024 * 1024, {}, cvm.hashes.initrd),
    ]);
    assert.equal(sha256(kernel), cvm.hashes.kernel, "TEE_PUBLIC_KERNEL_DIGEST_REJECTED");
    assert.equal(sha256(initrd), cvm.hashes.initrd, "TEE_PUBLIC_INITRD_DIGEST_REJECTED");
    // Independently recompute the quote-bound boot measurement from the
    // authenticated kernel, initrd and command line: TDX RTMR1/RTMR2, or the
    // whole SEV-SNP launch digest with the pinned OVMF.
    assert(verified.platform === "tdx" || verified.platform === "sev-snp", "TEE_CPU_PLATFORM_REJECTED");
    const boot = verified.platform === "tdx" ? computeBootMeasurements(kernel, initrd, verified.vmShape.memory_mb, expectedCommand) : undefined;
    const snpMeasurement = verified.platform === "sev-snp" ? computeSnpLaunchDigest(kernel, initrd, verified.vmShape.cpus, expectedCommand) : undefined;
    if (boot) {
      assert.equal(boot.rtmr1, verified.rtmr1, "TEE_PUBLIC_BOOT_MEASUREMENT_REJECTED");
      assert.equal(boot.rtmr2, verified.rtmr2, "TEE_PUBLIC_BOOT_MEASUREMENT_REJECTED");
    } else {
      assert.equal(snpMeasurement, verified.snpMeasurement, "TEE_PUBLIC_BOOT_MEASUREMENT_REJECTED");
    }

    // Select the registry root through the authenticated release, not delivery
    // metadata or a mutable tag. Anonymous GHCR pull tokens authorize reads only.
    const envelope = parseJson(raw);
    const codeCollateral = envelope.collateral.filter((item: any) => item.format === "https://tinfoil.sh/collateral/sigstore-code/v1");
    assert.equal(codeCollateral.length, 1, "TEE_CONTAINER_BUILD_REJECTED");
    assert(codeCollateral[0].id === "code" && codeCollateral[0].role === "reference-values", "TEE_CONTAINER_BUILD_REJECTED");
    const releaseInput = { repo, tag: verified.tag, deployment: artifact.toString("base64"), bundle: codeCollateral[0].data.sigstore_bundle };
    const runtime = await appraise(JSON.stringify(releaseInput), ["--runtime-config"]);
    assert(runtime.runtimeConstraintsVerified === true && runtime.authenticatedRelease === true && runtime.cpuVerified === false && runtime.gpuVerified === false && runtime.freshnessVerified === false && runtime.inferenceQualified === false &&
      runtime.profile === "tinfoil-vllm-v1" && runtime.repo === repo && runtime.tag === verified.tag && runtime.releaseCommit === verified.commit && runtime.deploymentDigest === verified.digest &&
      runtime.configDigest === sha256(source) && runtime.cvmTag === cvmTag, "TEE_RUNTIME_CONFIG_REJECTED");
    assert(runtime.subjectPredicateMatched === true && runtime.codeStatementDigest === verified.codeStatementDigest, "TEE_RUNTIME_CONFIG_REJECTED");
    const selected = await appraise(JSON.stringify(releaseInput), ["--container-reference"]);
    assert(selected.artifactReferenceVerified === true && selected.inferenceQualified === false &&
      selected.repo === repo && selected.releaseCommit === verified.commit && selected.deploymentDigest === verified.digest &&
      /^[a-f0-9]{64}$/.test(selected.imageDigest), "TEE_CONTAINER_BUILD_REJECTED");
    assert(selected.subjectPredicateMatched === true && selected.codeStatementDigest === verified.codeStatementDigest, "TEE_CONTAINER_BUILD_REJECTED");
    assert.equal(runtime.imageDigest, selected.imageDigest, "TEE_RUNTIME_CONFIG_REJECTED");
    let registryToken: string | undefined;
    async function registryArtifact(kind: "manifests" | "blobs", digest: string) {
      assert(/^sha256:[a-f0-9]{64}$/.test(digest), "TEE_CONTAINER_BUILD_REJECTED");
      const hit = cache?.get(digest, 128 * 1024);
      if (hit) { assert.equal(`sha256:${sha256(hit)}`, digest); return hit; }
      if (!registryToken) {
        const tokenResponse = parseJson(await get(`https://ghcr.io/token?service=ghcr.io&scope=repository:${repo}:pull`));
        assert(typeof tokenResponse.token === "string" && tokenResponse.token.length > 0 && tokenResponse.token.length < 8192, "TEE_PUBLIC_ARTIFACT_UNAVAILABLE");
        registryToken = tokenResponse.token;
      }
      const bytes = await get(`https://ghcr.io/v2/${repo}/${kind}/${digest}`, kind === "blobs" ? "follow" : "error", 128 * 1024, {
        authorization: `Bearer ${registryToken}`,
        accept: "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json",
      }, digest.slice(7));
      // Cross-origin blob redirects strip Authorization; the digest authenticates
      // public bytes regardless of the delivery origin.
      assert.equal(`sha256:${sha256(bytes)}`, digest, "TEE_CONTAINER_BUILD_REJECTED");
      return bytes;
    }
    const indexBytes = await registryArtifact("manifests", `sha256:${selected.imageDigest}`);
    const index = parseJson(indexBytes);
    assert(Array.isArray(index.manifests) && index.manifests.length === 2, "TEE_CONTAINER_BUILD_REJECTED");
    const engines = index.manifests.filter((item: any) => item.platform?.architecture === "amd64" && item.platform?.os === "linux");
    const proofs = index.manifests.filter((item: any) => item.annotations?.["vnd.docker.reference.type"] === "attestation-manifest");
    assert(engines.length === 1 && proofs.length === 1, "TEE_CONTAINER_BUILD_REJECTED");
    const [imageBytes, attestationBytes] = await Promise.all([
      registryArtifact("manifests", engines[0].digest), registryArtifact("manifests", proofs[0].digest),
    ]);
    const image = parseJson(imageBytes), attestation = parseJson(attestationBytes);
    assert(Array.isArray(attestation.layers) && attestation.layers.length === 1, "TEE_CONTAINER_BUILD_REJECTED");
    const [imageConfig, provenance] = await Promise.all([
      registryArtifact("blobs", image.config.digest), registryArtifact("blobs", attestation.layers[0].digest),
    ]);
    const container = await appraise(JSON.stringify({ ...releaseInput,
      index: indexBytes.toString("base64"), imageManifest: imageBytes.toString("base64"), imageConfig: imageConfig.toString("base64"),
      attestationManifest: attestationBytes.toString("base64"), provenance: provenance.toString("base64"),
    }), ["--container-build"]);
    assert(container.publisherEndorsedBuildMetadata === true && container.independentBuilderVerified === false && container.inferenceQualified === false &&
      container.deploymentDigest === verified.digest && container.releaseCommit === verified.commit && container.imageDigest === selected.imageDigest &&
      /^[a-f0-9]{40}$/.test(container.sourceCommit) && /^[a-f0-9]{64}$/.test(container.dockerfileDigest), "TEE_CONTAINER_BUILD_REJECTED");
    assert(container.subjectPredicateMatched === true && container.codeStatementDigest === verified.codeStatementDigest, "TEE_CONTAINER_BUILD_REJECTED");
    const commitsUrl = `https://api.github.com/repos/${repo}/git/commits/${verified.commit}`;
    const [commitBytes, dockerfile] = await Promise.all([
      get(commitsUrl, "error", 2 * 1024 * 1024, {}, undefined, true),
      get(`https://raw.githubusercontent.com/${repo}/${container.sourceCommit}/Dockerfile`, "error", 2 * 1024 * 1024, {}, container.dockerfileDigest),
    ]);
    await checked(commitsUrl, () => {
      const sourceCommit = parseJson(commitBytes);
      assert(Array.isArray(sourceCommit.parents) && sourceCommit.parents.length === 1 && sourceCommit.parents[0].sha === container.sourceCommit, "TEE_PUBLIC_CONTAINER_SOURCE_REJECTED");
    });
    assert.equal(sha256(dockerfile), container.dockerfileDigest, "TEE_PUBLIC_CONTAINER_SOURCE_REJECTED");
    return {
      ...verified, publicArtifactDigestMatched: true, publicSourceConfigMatched: true,
      sourceUrl: `https://github.com/${repo}/blob/${verified.commit}/tinfoil-config.yml`,
      releaseUrl: `https://github.com/${repo}/releases/tag/${verified.tag}`,
      cvmBuildVerified: true, cvmTag, cvmCommit: cvm.commit, cvmManifestDigest: cvm.manifestDigest,
      cvmSourceUrl: `https://github.com/tinfoilsh/cvmimage/tree/${cvm.commit}`,
      kernelDigestMatched: true, initrdDigestMatched: true, guestVerityRootAuthenticated: true,
      rtmr1Recomputed: boot?.rtmr1, rtmr2Recomputed: boot?.rtmr2, snpMeasurementRecomputed: snpMeasurement,
      containerBuild: { ...container, publicSourceParentMatched: true, publicDockerfileBytesMatched: true },
      runtimeConfig: runtime,
      independentRebuild: false, inferenceQualified: false,
    };
  } catch (error) {
    cache?.clear();
    signal.throwIfAborted();
    if (error instanceof TeeError && error.code === "TEE_PUBLIC_ARTIFACT_UNAVAILABLE") throw new TeeError(error.code, undefined, error.upstream);
    throw new TeeError("TEE_PUBLIC_BUILD_REJECTED");
  }
}

// Best effort: a cache that cannot be written only costs future requests.
async function persistMetadata(dir: string, entries: Map<string, Buffer>) {
  try {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    if (!await privateDirectory(dir)) return;
    for (const [path, bytes] of entries) {
      const temporary = `${path}.${randomBytes(8).toString("hex")}.tmp`;
      await writeFile(temporary, bytes, { mode: 0o600, flag: "wx" });
      await rename(temporary, path);
    }
  } catch { /* ignored */ }
}
