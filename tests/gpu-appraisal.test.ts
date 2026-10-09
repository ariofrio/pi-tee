import assert from "node:assert/strict";
import { test } from "node:test";
import { checkGpuAppraisal } from "../packages/tinfoil/src/worker-appraisal.js";
import { rateGpuAppraisal, GPU_POLICIES } from "../packages/core/src/gpu-appraisal.js";

// Policy over NVIDIA's verdict. Signature, reference and revocation results
// come from the real verifier in the live and collateral checks; these cases
// mutate an accepted verdict's shape to exercise the multi-GPU rules.
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
function claim(index: number, hwmodel = "GB110 A01 GSP BROM", vbios = "97.10.64.00.0C") {
  return {
    eat_nonce: nonce, hwmodel, measres: "success", dbgstat: "disabled", secboot: true, ueid: `device-${index}`,
    "x-nvidia-gpu-driver-version": "595.71.05", "x-nvidia-gpu-vbios-version": vbios,
    "x-nvidia-gpu-attestation-report-cert-chain": chain, "x-nvidia-gpu-driver-rim-cert-chain": chain, "x-nvidia-gpu-vbios-rim-cert-chain": chain,
    ...Object.fromEntries([
      "x-nvidia-gpu-arch-check", "x-nvidia-gpu-attestation-report-parsed", "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
      "x-nvidia-gpu-driver-rim-fetched", "x-nvidia-gpu-driver-rim-measurements-available", "x-nvidia-gpu-driver-rim-signature-verified",
      "x-nvidia-gpu-driver-rim-version-match", "x-nvidia-gpu-vbios-rim-fetched", "x-nvidia-gpu-vbios-rim-measurements-available",
      "x-nvidia-gpu-vbios-rim-signature-verified", "x-nvidia-gpu-vbios-rim-version-match", "x-nvidia-gpu-vbios-index-no-conflict",
      "x-nvidia-gpu-attestation-report-signature-verified", "x-nvidia-gpu-attestation-report-nonce-match",
    ].map(name => [name, true])),
  };
}
function verdict(claims: unknown[]) { return { code: 0, stdout: JSON.stringify({ result_code: 0, claims }) }; }
const eight = Array.from({ length: 8 }, (_, index) => claim(index));
const mptEvidence = Array.from({ length: 8 }, () => ({ arch: "BLACKWELL", evidence: report(1) }));

test("eight distinct Blackwell GPUs in MPT pass", () => {
  checkGpuAppraisal(verdict(eight), mptEvidence, nonce, 8);
});

test("GPU ratings distinguish complete protection, authenticated gaps and unknown coverage", () => {
  const binding = { cpuFresh: true, completeCoverage: true, cpuHash: true };
  const rate = (checked = verdict(eight), evidence = mptEvidence, count = 8, details = binding) =>
    rateGpuAppraisal(GPU_POLICIES, checked, evidence, nonce, count, details);
  assert.equal(rate().gpu, 1);
  assert.equal(rate(verdict(eight.map(c => ({ ...c, "x-nvidia-gpu-driver-version": "595.58.03" })))).gpu, 2);
  const hopper = [claim(0, "GH100 A01 GSP BROM", "96.00.D0.00.03"), claim(1, "GH100 A01 GSP BROM", "96.00.D0.00.03")];
  const gaps = rate(verdict(hopper), hopper.map(() => ({ arch: "HOPPER", evidence: report(2) })), 2);
  assert.equal(gaps.gpu, 2);
  assert.match(gaps.observed.join(" "), /NVSwitch/);
  assert.equal(rate(undefined, undefined, undefined, { ...binding, cpuHash: false }).gpu, 2);
  assert.equal(rate(undefined, undefined, undefined, { ...binding, completeCoverage: false }).gpu, 3);
  assert.equal(rate(undefined, undefined, undefined, { ...binding, cpuFresh: false }).gpu, 3);
  assert.equal(rate(verdict(eight.slice(0, 7))).gpu, 3);
  assert.equal(rate(verdict(eight.map(c => ({ ...c, ueid: "same" })))).gpu, 3);
  assert.equal(rate(verdict([{ ...eight[0], secboot: false }, ...eight.slice(1)])).gpu, 3);
  assert.equal(rate(verdict([{ ...eight[0], "x-nvidia-gpu-vbios-rim-cert-chain": { ...chain, "x-nvidia-cert-ocsp-status": "revoked" } }, ...eight.slice(1)])).gpu, 3);
});

test("multi-GPU appraisal rejects duplicated, mixed, missing, outdated and mis-moded devices", () => {
  const cases: [string, ReturnType<typeof verdict>, typeof mptEvidence, number, RegExp][] = [
    ["one report reused", verdict(eight.map(c => ({ ...c, ueid: "device-0" }))), mptEvidence, 8, /TEE_GPU_POLICY_REJECTED/],
    ["mixed hardware models", verdict([...eight.slice(0, 7), claim(7, "GB100 A01 GSP BROM", "97.00.D9.00.35")]), mptEvidence, 8, /TEE_GPU_POLICY_REJECTED/],
    ["fewer devices than the release declares", verdict(eight.slice(0, 7)), mptEvidence.slice(0, 7), 8, /TEE_GPU_POLICY_REJECTED/],
    ["older firmware", verdict([...eight.slice(0, 7), claim(7, "GB110 A01 GSP BROM", "97.10.64.00.0B")]), mptEvidence, 8, /TEE_GPU_POLICY_REJECTED/],
    ["one GPU in SPT among MPT", verdict(eight), [...mptEvidence.slice(0, 7), { arch: "BLACKWELL", evidence: report(0) }], 8, /TEE_GPU_MODE_REJECTED/],
    ["PPCIe", verdict(eight), mptEvidence.map(e => ({ ...e, evidence: report(2) })), 8, /TEE_GPU_MODE_REJECTED/],
    ["architecture mismatch", verdict(eight), mptEvidence.map(e => ({ ...e, arch: "HOPPER" })), 8, /TEE_GPU_POLICY_REJECTED/],
    ["Hopper multi-GPU", verdict(Array.from({ length: 2 }, (_, index) => claim(index, "GH100 A01 GSP BROM", "96.00.D0.00.03"))),
      Array.from({ length: 2 }, () => ({ arch: "HOPPER", evidence: report(1) })), 2, /TEE_GPU_POLICY_REJECTED/],
    ["revoked reference certificate", verdict([{ ...eight[0], "x-nvidia-gpu-vbios-rim-cert-chain": { ...chain, "x-nvidia-cert-ocsp-status": "revoked" } }, ...eight.slice(1)]),
      mptEvidence, 8, /TEE_GPU_POLICY_REJECTED/],
    ["NVIDIA failure", { code: 12, stdout: JSON.stringify({ result_code: 12, claims: eight }) }, mptEvidence, 8, /TEE_GPU_POLICY_REJECTED/],
  ];
  for (const [name, checked, evidence, count, expected] of cases) {
    assert.throws(() => checkGpuAppraisal(checked, evidence, nonce, count), expected, name);
  }
});

test("a single Hopper GPU must report SPT", () => {
  const one = [claim(0, "GH100 A01 GSP BROM", "96.00.D0.00.03")];
  checkGpuAppraisal(verdict(one), [{ arch: "HOPPER", evidence: report(0) }], nonce, 1);
  assert.throws(() => checkGpuAppraisal(verdict(one), [{ arch: "HOPPER", evidence: report(1) }], nonce, 1), /TEE_GPU_MODE_REJECTED/);
});
