import { randomBytes, createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import assert from "node:assert/strict";

// Evidence and public artifacts only: no login, inference or key release.
const [helperPath, fixturePath] = process.argv.slice(2);
assert(helperPath && process.argv.length <= 4, "usage: node tinfoil-public-build.mjs HELPER [NEW_EVIDENCE_FILE]");
const signal = AbortSignal.timeout(90000);
const host = "gemma4-31b-inf8-0.tinfoil.containers.tinfoil.dev";
const repo = "tinfoilsh/confidential-gemma4-31b";
const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");

async function get(url, redirect = "error", maxBytes = 2 * 1024 * 1024, headers = {}) {
  const response = await fetch(url, { signal, redirect, headers });
  assert(response.ok, "TEE_PUBLIC_ARTIFACT_UNAVAILABLE");
  assert(response.body, "TEE_PUBLIC_ARTIFACT_UNAVAILABLE");
  const chunks = [];
  let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length;
    assert(length <= maxBytes, "TEE_PUBLIC_ARTIFACT_TOO_LARGE");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

const nonce = randomBytes(32).toString("hex");
const raw = await get(`https://${host}/.well-known/tinfoil-attestation?nonce=${nonce}`);
// Pass the exact document bytes to the strict Go parser, without reserializing.
const input = `{"nonce":${JSON.stringify(nonce)},"envelope":${raw.toString("utf8")}}`;
function appraise(input, args = []) {
  return new Promise((resolveResult, reject) => {
    const child = execFile(resolve(helperPath), args, { env: { TZ: "UTC" }, signal, timeout: 60000, maxBuffer: 8192 }, (error, stdout) => {
      if (error) return reject(new Error("TEE_PUBLIC_BUILD_REJECTED"));
      try { resolveResult(JSON.parse(stdout)); } catch { reject(new Error("TEE_PUBLIC_BUILD_REJECTED")); }
    });
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}
const verified = await appraise(input);
assert(verified.cpuVerified && verified.publicBuildVerified && verified.inferenceQualified === false, "TEE_PUBLIC_BUILD_REJECTED");
assert.equal(verified.repo, repo);
assert(/^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(verified.tag));
assert(/^[a-f0-9]{40}$/.test(verified.commit));
assert(/^[a-f0-9]{64}$/.test(verified.digest));

// GitHub's public asset redirects carry no credentials. The authenticated
// subject digest, rather than HTTPS or the release filename, authenticates bytes.
const artifact = await get(`https://github.com/${repo}/releases/download/${verified.tag}/tinfoil-deployment.json`, "follow");
assert.equal(sha256(artifact), verified.digest, "TEE_PUBLIC_ARTIFACT_DIGEST_REJECTED");
const source = await get(`https://raw.githubusercontent.com/${repo}/${verified.commit}/tinfoil-config.yml`);
const deployment = JSON.parse(artifact);
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
const candidates = JSON.parse(await get(`https://api.github.com/repos/tinfoilsh/cvmimage/attestations/sha256:${sha256(manifest)}?per_page=100`));
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
const sha384 = bytes => createHash("sha384").update(bytes).digest();
let rtmr2 = Buffer.alloc(48);
for (const bytes of [Buffer.from(`${expectedCommand} initrd=initrd\0`, "utf16le"), initrd]) {
  rtmr2 = sha384(Buffer.concat([rtmr2, sha384(bytes)]));
}
assert.equal(rtmr2.toString("hex"), deployment.tdx_measurement.rtmr2, "TEE_PUBLIC_BOOT_MEASUREMENT_REJECTED");

// Select the registry root through the authenticated release, not delivery
// metadata or a mutable tag. Anonymous GHCR pull tokens authorize reads only.
const envelope = JSON.parse(raw);
const codeCollateral = envelope.collateral.filter(item => item.id === "code");
assert.equal(codeCollateral.length, 1, "TEE_CONTAINER_BUILD_REJECTED");
const releaseInput = { tag: verified.tag, deployment: artifact.toString("base64"), bundle: codeCollateral[0].data.sigstore_bundle };
const selected = await appraise(JSON.stringify(releaseInput), ["--container-reference"]);
assert(selected.artifactReferenceVerified === true && selected.inferenceQualified === false &&
  selected.repo === repo && selected.releaseCommit === verified.commit && selected.deploymentDigest === verified.digest &&
  /^[a-f0-9]{64}$/.test(selected.imageDigest), "TEE_CONTAINER_BUILD_REJECTED");
const tokenResponse = JSON.parse(await get(`https://ghcr.io/token?service=ghcr.io&scope=repository:${repo}:pull`));
assert(typeof tokenResponse.token === "string" && tokenResponse.token.length > 0 && tokenResponse.token.length < 8192, "TEE_PUBLIC_ARTIFACT_UNAVAILABLE");
async function registryArtifact(kind, digest) {
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
const index = JSON.parse(indexBytes);
assert(Array.isArray(index.manifests) && index.manifests.length === 2, "TEE_CONTAINER_BUILD_REJECTED");
const engines = index.manifests.filter(item => item.platform?.architecture === "amd64" && item.platform?.os === "linux");
const proofs = index.manifests.filter(item => item.annotations?.["vnd.docker.reference.type"] === "attestation-manifest");
assert(engines.length === 1 && proofs.length === 1, "TEE_CONTAINER_BUILD_REJECTED");
const [imageBytes, attestationBytes] = await Promise.all([
  registryArtifact("manifests", engines[0].digest), registryArtifact("manifests", proofs[0].digest),
]);
const image = JSON.parse(imageBytes), attestation = JSON.parse(attestationBytes);
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
const [sourceCommit, dockerfile] = await Promise.all([
  get(`https://api.github.com/repos/${repo}/git/commits/${verified.commit}`).then(bytes => JSON.parse(bytes)),
  get(`https://raw.githubusercontent.com/${repo}/${container.sourceCommit}/Dockerfile`),
]);
assert(Array.isArray(sourceCommit.parents) && sourceCommit.parents.length === 1 && sourceCommit.parents[0].sha === container.sourceCommit, "TEE_PUBLIC_CONTAINER_SOURCE_REJECTED");
assert.equal(sha256(dockerfile), container.dockerfileDigest, "TEE_PUBLIC_CONTAINER_SOURCE_REJECTED");
if (fixturePath) await writeFile(resolve(fixturePath), input, { mode: 0o600, flag: "wx" });
console.log(JSON.stringify({
  ...verified, host, publicArtifactDigestMatched: true, publicSourceConfigMatched: true,
  sourceUrl: `https://github.com/${repo}/blob/${verified.commit}/tinfoil-config.yml`,
  releaseUrl: `https://github.com/${repo}/releases/tag/${verified.tag}`,
  cvmBuildVerified: true, cvmTag, cvmCommit: cvm.commit, cvmManifestDigest: cvm.manifestDigest,
  cvmSourceUrl: `https://github.com/tinfoilsh/cvmimage/tree/${cvm.commit}`,
  kernelDigestMatched: true, initrdDigestMatched: true, guestVerityRootAuthenticated: true,
  rtmr2Recomputed: rtmr2.toString("hex"),
  containerBuild: { ...container, publicSourceParentMatched: true, publicDockerfileBytesMatched: true },
  independentRebuild: false, inferenceQualified: false,
}));
