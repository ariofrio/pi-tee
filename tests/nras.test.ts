import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { runNrasVerifier } from "../packages/core/src/nras.js";

const issuer = "https://nras.attestation.nvidia.com", nonce = "aa".repeat(32);
test("NRAS authenticates every detached device token and its overall digest before returning claims", async () => {
  const { privateKey, publicKey } = await generateKeyPair("ES384");
  const jwk = { ...await exportJWK(publicKey), kid: "test" };
  async function token(payload: Record<string, unknown>) {
    return new SignJWT(payload).setProtectedHeader({ alg: "ES384", kid: "test" }).setIssuer(issuer).setIssuedAt().setNotBefore("0s").setExpirationTime("1m").sign(privateKey);
  }
  const device = await token({ eat_nonce: nonce, ueid: "synthetic-device" });
  const digest = createHash("sha256").update(device).digest("hex");
  const overall = await token({ eat_nonce: nonce, "x-nvidia-overall-att-result": true, submods: { "GPU-0": ["DIGEST", ["SHA-256", digest]] } });
  const calls: string[] = [];
  const response = [["JWT", overall], { "GPU-0": device }];
  const fetch: typeof globalThis.fetch = async input => {
    const url = new URL(new Request(input).url); calls.push(url.href);
    return Response.json(url.pathname.includes("jwks") ? { keys: [jwk] } : response);
  };
  const result = await runNrasVerifier({ evidence: [{ arch: "HOPPER", evidence: "synthetic", certificate: "synthetic", nonce }], nonce, signal: AbortSignal.timeout(10000), fetch });
  assert.equal(result.code, 0);
  assert.equal(JSON.parse(result.stdout).claims[0].ueid, "synthetic-device");
  assert.ok(calls.every(url => url.startsWith(issuer + "/")));
  for (const bad of [
    [["JWT", overall], {}],
    [["JWT", overall], { "GPU-0": device + "x" }],
    [["JWT", await token({ eat_nonce: "bb".repeat(32), "x-nvidia-overall-att-result": true, submods: { "GPU-0": ["DIGEST", ["SHA-256", digest]] } })], { "GPU-0": device }],
    [["JWT", await token({ eat_nonce: nonce, "x-nvidia-overall-att-result": false, submods: { "GPU-0": ["DIGEST", ["SHA-256", digest]] } })], { "GPU-0": device }],
    [["JWT", await token({ eat_nonce: nonce, "x-nvidia-overall-att-result": true, submods: { "GPU-0": ["DIGEST", ["SHA-256", "00".repeat(32)]] } })], { "GPU-0": device }],
  ]) await assert.rejects(runNrasVerifier({ evidence: [{ arch: "HOPPER" }], nonce, signal: AbortSignal.timeout(10000), fetch: async input => Response.json(String(input).includes("jwks") ? { keys: [jwk] } : bad) }), /TEE_GPU_POLICY_REJECTED/);
});
