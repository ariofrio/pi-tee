import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { test } from "node:test";
import { verifyPublicBuildArtifacts } from "../packages/tinfoil/src/public-build.js";

const enabled = Boolean(process.env.PI_TEE_PUBLIC_BUILD_TEST_EVIDENCE && process.env.PI_TEE_PUBLIC_BUILD_TEST_HELPER && process.env.PI_TEE_BOOT_TEST_DIR);
const hash = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

test("the Node artifact chain rejects substituted delivery bytes using the real CPU and release verifiers", { skip: !enabled }, async () => {
  const evidence = JSON.parse(await readFile(process.env.PI_TEE_PUBLIC_BUILD_TEST_EVIDENCE!, "utf8"));
  const fixture = (name: string) => readFile(`tools/tinfoil-public-build/testdata/${name}`);
  const deployment = await fixture("gemma-v0.0.25-deployment.json");
  const config = Buffer.from(JSON.parse(deployment.toString()).config, "base64");
  const manifest = await fixture("cvm-v0.11.0-manifest.json");
  const cvmBundle = JSON.parse((await fixture("cvm-v0.11.0.bundle.json")).toString());
  const index = await fixture("gemma-v0.0.25-index.json");
  const image = await fixture("gemma-v0.0.25-image.json");
  const imageConfig = await fixture("gemma-v0.0.25-config.json");
  const attestation = await fixture("gemma-v0.0.25-attestation.json");
  const provenance = await fixture("gemma-v0.0.25-provenance.json");
  const proof = JSON.parse(provenance.toString());
  const dockerfile = Buffer.from(proof.predicate.runDetails.metadata.buildkit_metadata.source.infos[0].data, "base64");
  const repo = "tinfoilsh/confidential-gemma4-31b";
  const artifacts = new Map<string, Buffer>([
    [`https://github.com/${repo}/releases/download/v0.0.25/tinfoil-deployment.json`, deployment],
    [`https://raw.githubusercontent.com/${repo}/43dc8f6d1c4d9c1504559ab181cf9dfe00ad239b/tinfoil-config.yml`, config],
    ["https://images.tinfoil.sh/cvm/tinfoil-inference-v0.11.0-manifest.json", manifest],
    [`https://api.github.com/repos/tinfoilsh/cvmimage/attestations/sha256:${hash(manifest)}?per_page=100`, Buffer.from(JSON.stringify({ attestations: [{ bundle: cvmBundle }] }))],
    ["https://images.tinfoil.sh/cvm/tinfoil-inference-v0.11.0.vmlinuz", await readFile(resolve(process.env.PI_TEE_BOOT_TEST_DIR!, "tinfoil-inference-v0.11.0.vmlinuz"))],
    ["https://images.tinfoil.sh/cvm/tinfoil-inference-v0.11.0.initrd", await readFile(resolve(process.env.PI_TEE_BOOT_TEST_DIR!, "tinfoil-inference-v0.11.0.initrd"))],
    [`https://ghcr.io/token?service=ghcr.io&scope=repository:${repo}:pull`, Buffer.from('{"token":"synthetic-read-only-token"}')],
    [`https://api.github.com/repos/${repo}/git/commits/43dc8f6d1c4d9c1504559ab181cf9dfe00ad239b`, Buffer.from('{"parents":[{"sha":"bff40cb8bd650c01be92e0f4cd98c960dbb222d9"}]}')],
    [`https://raw.githubusercontent.com/${repo}/bff40cb8bd650c01be92e0f4cd98c960dbb222d9/Dockerfile`, dockerfile],
  ]);
  for (const [kind, bytes] of [["manifests", index], ["manifests", image], ["manifests", attestation], ["blobs", imageConfig], ["blobs", provenance]] as const) {
    artifacts.set(`https://ghcr.io/v2/${repo}/${kind}/sha256:${hash(bytes)}`, bytes);
  }
  const run = async (change?: { url: string; bytes: Buffer }) => {
    const requests: string[] = [];
    const result = verifyPublicBuildArtifacts({ helperPath: process.env.PI_TEE_PUBLIC_BUILD_TEST_HELPER!,
      raw: JSON.stringify(evidence.envelope), nonce: evidence.nonce, signal: AbortSignal.timeout(60000),
      evidenceFetch: async (input, init) => {
        const url = String(input); requests.push(url);
        assert.equal(init?.body, undefined, "No artifact check sends a prompt or credentials.");
        assert(!url.includes("chat/completions") && !url.includes("nvidia"));
        const bytes = change?.url === url ? change.bytes : artifacts.get(url);
        assert(bytes, `Unexpected delivery endpoint ${url}`);
        return new Response(new Uint8Array(bytes));
      },
    });
    return { result, requests };
  };
  const positive = await run();
  const verified = await positive.result;
  assert.equal(verified.inferenceQualified, false);
  assert.equal(verified.runtimeConfig.subjectPredicateMatched, true);
  assert.equal(verified.runtimeConfig.codeStatementDigest, verified.codeStatementDigest);
  for (const [url, bytes] of artifacts) {
    if (url.includes("ghcr.io/token")) continue;
    const altered = Buffer.from(bytes);
    altered[0] = altered[0]! ^ 1;
    const negative = await run({ url, bytes: altered });
    await assert.rejects(negative.result, /TEE_PUBLIC_BUILD_REJECTED/);
    assert(negative.requests.includes(url), "The substituted artifact must actually reach its check.");
  }
  for (const change of [
    { url: `https://api.github.com/repos/${repo}/git/commits/43dc8f6d1c4d9c1504559ab181cf9dfe00ad239b`, bytes: Buffer.from('{"parents":[{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}') },
    { url: `https://api.github.com/repos/tinfoilsh/cvmimage/attestations/sha256:${hash(manifest)}?per_page=100`, bytes: Buffer.from('{"attestations":[]}') },
    { url: `https://raw.githubusercontent.com/${repo}/43dc8f6d1c4d9c1504559ab181cf9dfe00ad239b/tinfoil-config.yml`, bytes: Buffer.concat([config, Buffer.from("\n")]) },
  ]) {
    const negative = await run(change);
    await assert.rejects(negative.result, /TEE_PUBLIC_BUILD_REJECTED/);
    assert(negative.requests.includes(change.url));
  }
});
