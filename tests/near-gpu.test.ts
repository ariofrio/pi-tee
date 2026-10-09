import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { openDirectNearTransport } from "../packages/nearai/src/direct.js";
import { checkNearGpuEvidence, nearModelVerification } from "../packages/nearai/src/gpu.js";

// Policy over NVIDIA's local verdict. Signature, reference and revocation
// results come from the real verifier in the live check; these cases mutate an
// accepted verdict's shape. NEAR currently serves from eight Hopper GPUs in
// PPCIe mode, which the shared default policy does not admit.
// A synthetic caller-supplied table, not a qualified policy: it only shows the table is honoured.
const ppcieTable = Object.freeze({ "GH100 A01 GSP BROM": Object.freeze({ arch: "HOPPER", driver: "595.58.03", vbios: "96.00.CF.00.02", maxGpus: 8, multiGpuMode: "ppcie" as const }) });
function report(mode: number) {
  const request = Buffer.alloc(37);
  request[0] = 0x11; request[1] = 0xe0;
  const response = Buffer.alloc(8);
  response[0] = 0x11; response[1] = 0x60; response[4] = 1;
  response.writeUIntLE(7, 5, 3);
  const opaque = Buffer.from([34, 0, 2, 0, 1, 0, 36, 0, 2, 0, mode, 0]);
  const length = Buffer.alloc(2); length.writeUInt16LE(opaque.length);
  return Buffer.concat([request, response, Buffer.alloc(7), Buffer.alloc(32), length, opaque, Buffer.alloc(96)]).toString("base64");
}
const nonce = "ab".repeat(32);
const chain = { "x-nvidia-cert-status": "valid", "x-nvidia-cert-ocsp-status": "good", "x-nvidia-cert-ocsp-response-valid": true, "x-nvidia-cert-ocsp-nonce-matches": true };
function claim(index: number, overrides: Record<string, unknown> = {}) {
  return {
    eat_nonce: nonce, hwmodel: "GH100 A01 GSP BROM", measres: "success", dbgstat: "disabled", secboot: true, ueid: `device-${index}`,
    "x-nvidia-gpu-driver-version": "595.58.03", "x-nvidia-gpu-vbios-version": "96.00.CF.00.02",
    "x-nvidia-gpu-attestation-report-cert-chain": chain, "x-nvidia-gpu-driver-rim-cert-chain": chain, "x-nvidia-gpu-vbios-rim-cert-chain": chain,
    ...Object.fromEntries([
      "x-nvidia-gpu-arch-check", "x-nvidia-gpu-attestation-report-parsed", "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
      "x-nvidia-gpu-driver-rim-fetched", "x-nvidia-gpu-driver-rim-measurements-available", "x-nvidia-gpu-driver-rim-signature-verified",
      "x-nvidia-gpu-driver-rim-version-match", "x-nvidia-gpu-vbios-rim-fetched", "x-nvidia-gpu-vbios-rim-measurements-available",
      "x-nvidia-gpu-vbios-rim-signature-verified", "x-nvidia-gpu-vbios-rim-version-match", "x-nvidia-gpu-vbios-index-no-conflict",
      "x-nvidia-gpu-attestation-report-signature-verified", "x-nvidia-gpu-attestation-report-nonce-match",
    ].map(name => [name, true])),
    ...overrides,
  };
}
const verdict = (claims: unknown[]) => ({ code: 0, stdout: JSON.stringify({ result_code: 0, claims }) });
const item = (mode = 2) => ({ arch: "HOPPER", certificate: "c3ludGhldGlj", evidence: report(mode), nonce });
const payload = (items = Array.from({ length: 8 }, () => item()), extra: Record<string, unknown> = {}) => JSON.stringify({ arch: "HOPPER", evidence_list: items, nonce, ...extra });
const eight = Array.from({ length: 8 }, (_, index) => claim(index));

async function check(text: string, result: ReturnType<typeof verdict>, policy: typeof ppcieTable | "default" = ppcieTable) {
  const calls: { evidence: unknown[]; nonce: string }[] = [];
  await checkNearGpuEvidence(text, { signal: AbortSignal.timeout(10000), policy: policy === "default" ? undefined : policy, run: async options => { calls.push(options); return result; } });
  return calls;
}

test("by default NEAR's eight PPCIe Hopper GPUs fail closed under the shared GPU policy", async () => {
  await assert.rejects(check(payload(), verdict(eight), "default"), /TEE_GPU_POLICY_REJECTED/);
});

test("a caller-supplied GPU policy table decides admission after NVIDIA's local verifier", async () => {
  const calls = await check(payload(), verdict(eight));
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.nonce, nonce, "The verifier checks every report against the payload nonce the SDK matched to the client nonce.");
  assert.equal(calls[0]!.evidence.length, 8);
});

test("NEAR GPU evidence fails closed on payload, verdict, device, version and mode faults", async () => {
  const cases: [string, string, ReturnType<typeof verdict>, RegExp][] = [
    ["malformed payload", "{", verdict(eight), /TEE_GPU_POLICY_REJECTED/],
    ["unexpected field", payload(undefined, { verifier: "nras" }), verdict(eight), /TEE_GPU_POLICY_REJECTED/],
    ["item nonce differs", payload([...Array.from({ length: 7 }, () => item()), { ...item(), nonce: "cd".repeat(32) }]), verdict(eight), /TEE_GPU_POLICY_REJECTED/],
    ["fewer reports than claims", payload(Array.from({ length: 7 }, () => item())), verdict(eight), /TEE_GPU_POLICY_REJECTED/],
    ["more than eight GPUs", payload(Array.from({ length: 9 }, () => item())), verdict([...eight, claim(8)]), /TEE_GPU_POLICY_REJECTED/],
    ["one report reused", payload(), verdict(eight.map(c => ({ ...c, ueid: "device-0" }))), /TEE_GPU_POLICY_REJECTED/],
    ["older VBIOS", payload(), verdict([...eight.slice(0, 7), claim(7, { "x-nvidia-gpu-vbios-version": "96.00.CF.00.01" })]), /TEE_GPU_POLICY_REJECTED/],
    ["older driver", payload(), verdict([...eight.slice(0, 7), claim(7, { "x-nvidia-gpu-driver-version": "595.58.02" })]), /TEE_GPU_POLICY_REJECTED/],
    ["unsupported hardware model", payload(), verdict(eight.map(c => ({ ...c, hwmodel: "GB100 A01 GSP BROM" }))), /TEE_GPU_POLICY_REJECTED/],
    ["debug enabled", payload(), verdict([claim(0, { dbgstat: "enabled" }), ...eight.slice(1)]), /TEE_GPU_POLICY_REJECTED/],
    ["revoked reference certificate", payload(), verdict([claim(0, { "x-nvidia-gpu-vbios-rim-cert-chain": { ...chain, "x-nvidia-cert-ocsp-status": "revoked" } }), ...eight.slice(1)]), /TEE_GPU_POLICY_REJECTED/],
    ["stale nonce in a report", payload(), verdict([claim(0, { eat_nonce: "cd".repeat(32) }), ...eight.slice(1)]), /TEE_GPU_POLICY_REJECTED/],
    ["MPT instead of PPCIe", payload(Array.from({ length: 8 }, () => item(1))), verdict(eight), /TEE_GPU_MODE_REJECTED/],
    ["NVIDIA failure", payload(), { code: 12, stdout: JSON.stringify({ result_code: 12, claims: eight }) }, /TEE_GPU_POLICY_REJECTED/],
  ];
  for (const [name, text, result, expected] of cases) await assert.rejects(check(text, result), expected, name);
});

test("the direct route appraises GPU evidence locally and never contacts NRAS", async () => {
  const fixture = JSON.parse(await readFile("tests/fixtures/near-glm-direct-attestation.json", "utf8"));
  const contacted: string[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    contacted.push(new URL(new Request(input, init).url).host);
    throw new Error("network disabled in this test");
  }) as typeof fetch;
  const channelRequests: string[] = [];
  const gpuRuns: { evidence: unknown[]; nonce: string }[] = [];
  // Serves the recorded public report under the client's fresh nonce: the
  // evidence is no longer genuine, so verification must fail before inference.
  const channel = {
    async request(request: Request) {
      const url = new URL(request.url);
      channelRequests.push(`${request.method} ${url.pathname}`);
      if (url.pathname !== "/v1/attestation/report") throw new Error("unexpected request");
      const fresh = url.searchParams.get("nonce")!;
      const swap = (attestation: any) => {
        const gpu = JSON.parse(attestation.nvidia_payload);
        return { ...attestation, request_nonce: fresh, nvidia_payload: JSON.stringify({ ...gpu, nonce: fresh, evidence_list: gpu.evidence_list.map((item: object) => ({ ...item, nonce: fresh })) }) };
      };
      const body = { ...swap(fixture), all_attestations: fixture.all_attestations.map(swap) };
      return { response: Response.json(body), peerSpkiFingerprint: fixture.tls_cert_fingerprint };
    },
    fetch: async () => { throw new Error("unexpected fetch"); },
    approve() { throw new Error("unexpected approval"); },
    close() {},
  };
  try {
    await assert.rejects(openDirectNearTransport("synthetic-key", AbortSignal.timeout(30000), { model: "z-ai/glm-5.3-flash", hostname: "glm-5-3-flash.completions.near.ai" }, {
      channel, cpu: { collateral: async () => { throw new Error("synthetic CPU failure"); } },
      runNvidiaVerifier: async options => { gpuRuns.push(options); return verdict([]); },
    }));
  } finally { globalThis.fetch = realFetch; }
  assert.ok(!contacted.some(host => host.endsWith("nvidia.com")), `NVIDIA services are reached only from the verifier's bridge: ${contacted.join(", ")}`);
  assert.deepEqual(channelRequests, ["GET /v1/attestation/report"], "No credentials or inference without verified evidence.");
  assert.ok(gpuRuns.length >= 1, "The local NVIDIA verifier appraised the GPU evidence.");
  assert.ok(gpuRuns.every(run => run.nonce !== fixture.request_nonce && /^[a-f0-9]{64}$/.test(run.nonce)), "Each appraisal uses the client's fresh nonce.");
});

test("GPU evidence that reaches the SDK is rejected locally, never submitted to NRAS", async () => {
  const fixture = JSON.parse(await readFile("tests/fixtures/near-glm-direct-attestation.json", "utf8"));
  const { verifyModelAttestation } = await import("@nearai/inference-sdk/node");
  const contacted: string[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    contacted.push(new URL(new Request(input, init).url).host);
    throw new Error("network disabled in this test");
  }) as typeof fetch;
  let gpuError: unknown;
  try {
    // The routes strip GPU payloads before SDK appraisal. This covers an SDK
    // path that still presents one: the model verifier must not fall back to NRAS.
    const { policy, verifiers } = nearModelVerification(async () => { throw new Error("synthetic CPU failure"); });
    await assert.rejects(verifyModelAttestation({
      attestation: { nonce: fixture.request_nonce, signer: { signingAlgo: "ed25519", signingAddress: fixture.signing_address },
        intelQuote: fixture.intel_quote, eventLog: fixture.event_log, appCompose: "", nvidiaPayload: fixture.nvidia_payload },
      clientBinding: { nonce: fixture.request_nonce }, policy,
      verifiers: { ...verifiers, gpuEvidence: verifiers.gpuEvidence && (async payload => {
        try { await verifiers.gpuEvidence!(payload); } catch (error) { gpuError = error; throw error; }
      }) },
    }));
    await new Promise(resolve => setTimeout(resolve, 100));
  } finally { globalThis.fetch = realFetch; }
  assert.deepEqual(contacted, []);
  assert.match(String(gpuError), /TEE_GPU_POLICY_REJECTED/);
});
