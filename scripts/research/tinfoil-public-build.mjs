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

async function get(url, redirect = "error") {
  const response = await fetch(url, { signal, redirect });
  assert(response.ok, "TEE_PUBLIC_ARTIFACT_UNAVAILABLE");
  assert(response.body, "TEE_PUBLIC_ARTIFACT_UNAVAILABLE");
  const chunks = [];
  let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length;
    assert(length <= 2 * 1024 * 1024, "TEE_PUBLIC_ARTIFACT_TOO_LARGE");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

const nonce = randomBytes(32).toString("hex");
const raw = await get(`https://${host}/.well-known/tinfoil-attestation?nonce=${nonce}`);
// Pass the exact document bytes to the strict Go parser, without reserializing.
const input = `{"nonce":${JSON.stringify(nonce)},"envelope":${raw.toString("utf8")}}`;
const verified = await new Promise((resolveResult, reject) => {
  const child = execFile(resolve(helperPath), [], { env: { TZ: "UTC" }, signal, timeout: 60000, maxBuffer: 8192 }, (error, stdout) => {
    if (error) return reject(new Error("TEE_PUBLIC_BUILD_REJECTED"));
    try { resolveResult(JSON.parse(stdout)); } catch { reject(new Error("TEE_PUBLIC_BUILD_REJECTED")); }
  });
  child.stdin.on("error", () => {});
  child.stdin.end(input);
});
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
if (fixturePath) await writeFile(resolve(fixturePath), input, { mode: 0o600, flag: "wx" });
console.log(JSON.stringify({
  ...verified, host, publicArtifactDigestMatched: true, publicSourceConfigMatched: true,
  sourceUrl: `https://github.com/${repo}/blob/${verified.commit}/tinfoil-config.yml`,
  releaseUrl: `https://github.com/${repo}/releases/tag/${verified.tag}`,
  independentRebuild: false, inferenceQualified: false,
}));
