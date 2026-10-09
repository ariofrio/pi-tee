import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { rateGpuAppraisal, GPU_POLICIES } from "../packages/core/src/gpu-appraisal.js";
import { claim, report, nonce as gpuNonce } from "./gpu-fixture.js";
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


test("signed NRAS device claims face the same coverage, firmware, revocation and mode gates", async () => {
  const { privateKey, publicKey } = await generateKeyPair("ES384");
  const jwk = { ...await exportJWK(publicKey), kid: "rating" };
  const sign = (payload: Record<string, unknown>) => new SignJWT(payload).setProtectedHeader({ alg: "ES384", kid: "rating" }).setIssuer(issuer).setIssuedAt().setNotBefore("0s").setExpirationTime("1m").sign(privateKey);
  const evidence = [{ arch: "BLACKWELL", evidence: report(0) }];
  for (const [changes, expected] of [
    [{}, 1], [{ "x-nvidia-gpu-driver-version": "595.58.03" }, 2], [{ secboot: false }, 3],
    [{ "x-nvidia-gpu-vbios-rim-cert-chain": { "x-nvidia-cert-status": "valid", "x-nvidia-cert-ocsp-status": "revoked", "x-nvidia-cert-ocsp-response-valid": true, "x-nvidia-cert-ocsp-nonce-matches": true } }, 3],
  ] as const) {
    const device = await sign({ ...claim(0), ...changes });
    const overall = await sign({ eat_nonce: gpuNonce, "x-nvidia-overall-att-result": true, submods: { "GPU-0": ["DIGEST", ["SHA-256", createHash("sha256").update(device).digest("hex")]] } });
    const checked = await runNrasVerifier({ evidence, nonce: gpuNonce, signal: AbortSignal.timeout(5000), fetch: async input => Response.json(String(input).includes("jwks") ? { keys: [jwk] } : [["JWT", overall], { "GPU-0": device }]) });
    const rate = (completeCoverage: boolean, mode = 0) => rateGpuAppraisal(GPU_POLICIES, checked, [{ arch: "BLACKWELL", evidence: report(mode) }], gpuNonce, 1, { cpuFresh: true, cpuHash: true, completeCoverage });
    assert.equal(rate(true).gpu, expected); assert.equal(rate(false).gpu, 3); assert.equal(rate(true, 2).gpu, 3);
  }
});
