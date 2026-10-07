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

async function get(url, redirect = "error", maxBytes = 2 * 1024 * 1024) {
  const response = await fetch(url, { signal, redirect });
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
if (fixturePath) await writeFile(resolve(fixturePath), input, { mode: 0o600, flag: "wx" });
console.log(JSON.stringify({
  ...verified, host, publicArtifactDigestMatched: true, publicSourceConfigMatched: true,
  sourceUrl: `https://github.com/${repo}/blob/${verified.commit}/tinfoil-config.yml`,
  releaseUrl: `https://github.com/${repo}/releases/tag/${verified.tag}`,
  cvmBuildVerified: true, cvmTag, cvmCommit: cvm.commit, cvmManifestDigest: cvm.manifestDigest,
  cvmSourceUrl: `https://github.com/tinfoilsh/cvmimage/tree/${cvm.commit}`,
  kernelDigestMatched: true, initrdDigestMatched: true, guestVerityRootAuthenticated: true,
  rtmr2Recomputed: rtmr2.toString("hex"),
  independentRebuild: false, inferenceQualified: false,
}));
