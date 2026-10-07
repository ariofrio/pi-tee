import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readBoundedBody, TeeError } from "pi-tee-core";
import assert from "node:assert/strict";
import { computeBootMeasurements } from "./boot-measurements.js";

const host = "gemma4-31b-inf8-0.tinfoil.containers.tinfoil.dev";
const repo = "tinfoilsh/confidential-gemma4-31b";
const parseJson = (bytes: string | Uint8Array): any => JSON.parse(typeof bytes === "string" ? bytes : new TextDecoder("utf-8", { fatal: true }).decode(bytes));
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

// Artifact authentication only. Callers must independently appraise the CPU-bound
// GPU bytes and qualify runtime/key/channel behavior before production admission.
export async function verifyPublicBuildArtifacts(options: {
  helperPath: string; raw: string; nonce: string; signal: AbortSignal; evidenceFetch?: typeof globalThis.fetch;
}) {
  const { helperPath, raw, nonce, signal } = options;
  const evidenceFetch = options.evidenceFetch ?? globalThis.fetch;
  async function get(url: string, redirect: RequestRedirect = "error", maxBytes = 2 * 1024 * 1024, headers: Record<string, string> = {}): Promise<Buffer> {
    const response = await evidenceFetch(url, { signal, redirect, headers });
    assert(response.ok && response.body, "TEE_PUBLIC_ARTIFACT_UNAVAILABLE");
    return Buffer.from(await readBoundedBody(response.body, maxBytes, signal));
  }
  const input = `{"nonce":${JSON.stringify(nonce)},"envelope":${raw}}`;
  function appraise(input: string, args: string[] = []): Promise<any> {
    return new Promise((resolveResult, reject) => {
      const child = execFile(helperPath, args, { env: { TZ: "UTC" }, signal, timeout: 60000, maxBuffer: 16384 }, (error, stdout) => {
        if (error) return reject(new TeeError("TEE_PUBLIC_BUILD_REJECTED"));
        try { resolveResult(parseJson(stdout)); } catch { reject(new TeeError("TEE_PUBLIC_BUILD_REJECTED")); }
      });
      child.stdin?.on("error", () => {});
      child.stdin?.end(input);
    });
  }
  try {
    const verified = await appraise(input);
    assert(verified.cpuVerified === true && verified.publicBuildVerified === true && verified.inferenceQualified === false, "TEE_PUBLIC_BUILD_REJECTED");
    assert.equal(verified.repo, repo);
    assert(/^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(verified.tag));
    assert(/^[a-f0-9]{40}$/.test(verified.commit));
    assert(/^[a-f0-9]{64}$/.test(verified.digest));
    assert(/^[a-f0-9]{64}$/.test(verified.codeStatementDigest));

    // GitHub's public asset redirects carry no credentials. The authenticated
    // subject digest, rather than HTTPS or the release filename, authenticates bytes.
    const artifact = await get(`https://github.com/${repo}/releases/download/${verified.tag}/tinfoil-deployment.json`, "follow");
    assert.equal(sha256(artifact), verified.digest, "TEE_PUBLIC_ARTIFACT_DIGEST_REJECTED");
    const source = await get(`https://raw.githubusercontent.com/${repo}/${verified.commit}/tinfoil-config.yml`);
    const deployment = parseJson(artifact);
    assert(Buffer.from(deployment.config, "base64").equals(source), "TEE_PUBLIC_SOURCE_CONFIG_REJECTED");
    assert(deployment.cmdline.split(" ").includes(`tinfoil-config-hash=${sha256(source)}`), "TEE_PUBLIC_SOURCE_CONFIG_REJECTED");
    assert(deployment.hashes && /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(deployment.hashes.version), "TEE_CVM_BUILD_REJECTED");
    const cvmTag = deployment.hashes.version;
    const manifestName = `tinfoil-inference-${cvmTag}-manifest.json`;
    const manifest = await get(`https://images.tinfoil.sh/cvm/${manifestName}`);
    // Public delivery can substitute or withhold bundles. Only the local verifier
    // can authorize the exact release workflow, source commit and artifact bytes.
    // This bounded page is a candidate set, not an assertion that every attestation
    // was examined. No matching candidate means failure, never unchecked acceptance.
    const candidates = parseJson(await get(`https://api.github.com/repos/tinfoilsh/cvmimage/attestations/sha256:${sha256(manifest)}?per_page=100`));
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
    for (const name of ["version", "root", "initrd", "kernel", "raw"]) {
      assert.equal(deployment.hashes[name], cvm.hashes[name], "TEE_CVM_MANIFEST_MISMATCH");
    }
    const expectedCommand = `readonly=on pci=realloc,nocrs modprobe.blacklist=nouveau nouveau.modeset=0 root=/dev/mapper/root roothash=${cvm.hashes.root} tinfoil-config-hash=${sha256(source)}`;
    assert.equal(deployment.cmdline, expectedCommand, "TEE_PUBLIC_BOOT_COMMAND_REJECTED");
    const [kernel, initrd] = await Promise.all([
      get(`https://images.tinfoil.sh/cvm/tinfoil-inference-${cvmTag}.vmlinuz`, "error", 32 * 1024 * 1024),
      get(`https://images.tinfoil.sh/cvm/tinfoil-inference-${cvmTag}.initrd`, "error", 32 * 1024 * 1024),
    ]);
    assert.equal(sha256(kernel), cvm.hashes.kernel, "TEE_PUBLIC_KERNEL_DIGEST_REJECTED");
    assert.equal(sha256(initrd), cvm.hashes.initrd, "TEE_PUBLIC_INITRD_DIGEST_REJECTED");
    const boot = computeBootMeasurements(kernel, initrd, verified.vmShape.memory_mb, expectedCommand);
    assert.equal(boot.rtmr1, verified.rtmr1, "TEE_PUBLIC_BOOT_MEASUREMENT_REJECTED");
    assert.equal(boot.rtmr2, verified.rtmr2, "TEE_PUBLIC_BOOT_MEASUREMENT_REJECTED");

    // Select the registry root through the authenticated release, not delivery
    // metadata or a mutable tag. Anonymous GHCR pull tokens authorize reads only.
    const envelope = parseJson(raw);
    const codeCollateral = envelope.collateral.filter((item: any) => item.format === "https://tinfoil.sh/collateral/sigstore-code/v1");
    assert.equal(codeCollateral.length, 1, "TEE_CONTAINER_BUILD_REJECTED");
    assert(codeCollateral[0].id === "code" && codeCollateral[0].role === "reference-values", "TEE_CONTAINER_BUILD_REJECTED");
    const releaseInput = { tag: verified.tag, deployment: artifact.toString("base64"), bundle: codeCollateral[0].data.sigstore_bundle };
    const runtime = await appraise(JSON.stringify(releaseInput), ["--runtime-config"]);
    assert(runtime.runtimeConstraintsVerified === true && runtime.authenticatedRelease === true && runtime.cpuVerified === false && runtime.gpuVerified === false && runtime.freshnessVerified === false && runtime.inferenceQualified === false &&
      runtime.profile === "gemma-single-gpu-v1" && runtime.repo === repo && runtime.tag === verified.tag && runtime.releaseCommit === verified.commit && runtime.deploymentDigest === verified.digest &&
      runtime.configDigest === sha256(source) && runtime.cvmTag === cvmTag, "TEE_RUNTIME_CONFIG_REJECTED");
    assert(runtime.subjectPredicateMatched === true && runtime.codeStatementDigest === verified.codeStatementDigest, "TEE_RUNTIME_CONFIG_REJECTED");
    const selected = await appraise(JSON.stringify(releaseInput), ["--container-reference"]);
    assert(selected.artifactReferenceVerified === true && selected.inferenceQualified === false &&
      selected.repo === repo && selected.releaseCommit === verified.commit && selected.deploymentDigest === verified.digest &&
      /^[a-f0-9]{64}$/.test(selected.imageDigest), "TEE_CONTAINER_BUILD_REJECTED");
    assert(selected.subjectPredicateMatched === true && selected.codeStatementDigest === verified.codeStatementDigest, "TEE_CONTAINER_BUILD_REJECTED");
    assert.equal(runtime.imageDigest, selected.imageDigest, "TEE_RUNTIME_CONFIG_REJECTED");
    const tokenResponse = parseJson(await get(`https://ghcr.io/token?service=ghcr.io&scope=repository:${repo}:pull`));
    assert(typeof tokenResponse.token === "string" && tokenResponse.token.length > 0 && tokenResponse.token.length < 8192, "TEE_PUBLIC_ARTIFACT_UNAVAILABLE");
    async function registryArtifact(kind: "manifests" | "blobs", digest: string) {
      assert(/^sha256:[a-f0-9]{64}$/.test(digest), "TEE_CONTAINER_BUILD_REJECTED");
      const bytes = await get(`https://ghcr.io/v2/${repo}/${kind}/${digest}`, kind === "blobs" ? "follow" : "error", 128 * 1024, {
        authorization: `Bearer ${tokenResponse.token}`,
        accept: "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json",
      });
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
    const [sourceCommit, dockerfile] = await Promise.all([
      get(`https://api.github.com/repos/${repo}/git/commits/${verified.commit}`).then(bytes => parseJson(bytes)),
      get(`https://raw.githubusercontent.com/${repo}/${container.sourceCommit}/Dockerfile`),
    ]);
    assert(Array.isArray(sourceCommit.parents) && sourceCommit.parents.length === 1 && sourceCommit.parents[0].sha === container.sourceCommit, "TEE_PUBLIC_CONTAINER_SOURCE_REJECTED");
    assert.equal(sha256(dockerfile), container.dockerfileDigest, "TEE_PUBLIC_CONTAINER_SOURCE_REJECTED");
    return {
      ...verified, host, publicArtifactDigestMatched: true, publicSourceConfigMatched: true,
      sourceUrl: `https://github.com/${repo}/blob/${verified.commit}/tinfoil-config.yml`,
      releaseUrl: `https://github.com/${repo}/releases/tag/${verified.tag}`,
      cvmBuildVerified: true, cvmTag, cvmCommit: cvm.commit, cvmManifestDigest: cvm.manifestDigest,
      cvmSourceUrl: `https://github.com/tinfoilsh/cvmimage/tree/${cvm.commit}`,
      kernelDigestMatched: true, initrdDigestMatched: true, guestVerityRootAuthenticated: true,
      rtmr1Recomputed: boot.rtmr1, rtmr2Recomputed: boot.rtmr2,
      containerBuild: { ...container, publicSourceParentMatched: true, publicDockerfileBytesMatched: true },
      runtimeConfig: runtime,
      independentRebuild: false, inferenceQualified: false,
    };
  } catch (error) {
    signal.throwIfAborted();
    throw new TeeError("TEE_PUBLIC_BUILD_REJECTED");
  }
}
