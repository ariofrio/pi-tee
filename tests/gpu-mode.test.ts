import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { gpuVersionsAllowed, requiredGpuMode } from "../packages/tinfoil/src/gpu-policy.js";

// The evidence CLI parses protocol fields; it never authenticates a device.
// Numeric expectations follow NVIDIA's Python verifier, not our parser.
function report(mode: number) {
  const request = Buffer.alloc(37);
  request[0] = 0x11; request[1] = 0xe0;
  const response = Buffer.alloc(8);
  response[0] = 0x11; response[1] = 0x60; response[4] = 1;
  response.writeUIntLE(7, 5, 3);
  const opaque = Buffer.from([34, 0, 2, 0, 1, 0, 36, 0, 2, 0, mode, 0]);
  const length = Buffer.alloc(2); length.writeUInt16LE(opaque.length);
  return Buffer.concat([request, response, Buffer.alloc(7), Buffer.alloc(32), length, opaque, Buffer.alloc(96)]);
}

test("the GPU evidence CLI follows NVIDIA's SPT/MPT/PPCIe numbering without claiming signature verification", () => {
  for (const [value, expected] of [[0, "spt"], [1, "mpt"], [2, "ppcie"]] as const) {
    const result = spawnSync(process.execPath, ["--import", "tsx", "scripts/research/nvidia-gpu-mode.ts"], {
      input: JSON.stringify({ report: report(value).toString("base64") }), encoding: "utf8", timeout: 10000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { mode: expected, gpuSignatureVerified: false, inferenceQualified: false });
  }
});

test("the GPU evidence CLI rejects ambiguous, unsupported and truncated mode fields", () => {
  const valid = report(0);
  const unknownVersion = Buffer.from(valid); unknownVersion[90] = 2;
  // Replace the feature's type with a second version field of the same size.
  const duplicateVersion = Buffer.from(valid); duplicateVersion[92] = 34;
  const overflowingField = Buffer.from(valid); overflowingField[94] = 255;
  for (const raw of [report(3), unknownVersion, duplicateVersion, overflowingField, valid.subarray(0, valid.length - 1), Buffer.concat([valid, Buffer.from([0])])]) {
    const result = spawnSync(process.execPath, ["--import", "tsx", "scripts/research/nvidia-gpu-mode.ts"], {
      input: JSON.stringify({ report: raw.toString("base64") }), encoding: "utf8", timeout: 10000,
    });
    assert.equal(result.status, 1);
    assert.deepEqual(JSON.parse(result.stdout), { failure: "TEE_GPU_MODE_REJECTED", gpuSignatureVerified: false, inferenceQualified: false });
  }
});

test("GPU version floors are per hardware model and admit authenticated upgrades only", () => {
  for (const [hwmodel, driver, vbios, compatible] of [
    ["GH100 A01 GSP BROM", "595.71.05", "96.00.D0.00.03", true],
    ["GH100 A01 GSP BROM", "596.10.01", "96.00.DA.00.01", true],
    ["GH100 A01 GSP BROM", "595.71.04", "96.00.D9.00.02", false],
    ["GH100 A01 GSP BROM", "595.71.05", "96.00.D0.00.02", false],
    ["GB100 A01 GSP BROM", "595.71.05", "97.00.D9.00.35", true],
    ["GB100 A01 GSP BROM", "595.71.05", "97.00.D9.00.34", false],
    // Another model's numbering cannot satisfy a floor.
    ["GB100 A01 GSP BROM", "595.71.05", "96.00.FF.00.FF", false],
    ["GB110 A01 GSP BROM", "595.71.05", "97.10.64.00.0C", true],
    ["GB110 A01 GSP BROM", "595.71.05", "97.00.FF.00.FF", false],
    ["GH200 A01 GSP BROM", "595.71.05", "96.00.D9.00.02", false],
    ["GH100 A01 GSP BROM", "595.71.05-extra", "96.00.D9.00.02", false],
    ["GH100 A01 GSP BROM", "595.71.05", "96.00.D9.00.02.00", false],
    ["GH100 A01 GSP BROM", "99999999999999.1.1", "96.00.D9.00.02", false],
  ] as const) assert.equal(gpuVersionsAllowed(hwmodel, driver, vbios), compatible, `${hwmodel} ${driver} ${vbios}`);
});

test("one GPU must report SPT; several Blackwell GPUs must report MPT; Hopper multi-GPU is unsupported", () => {
  assert.equal(requiredGpuMode("GH100 A01 GSP BROM", 1), "spt");
  assert.equal(requiredGpuMode("GH100 A01 GSP BROM", 2), undefined);
  assert.equal(requiredGpuMode("GB100 A01 GSP BROM", 1), "spt");
  assert.equal(requiredGpuMode("GB110 A01 GSP BROM", 8), "mpt");
  assert.equal(requiredGpuMode("GB110 A01 GSP BROM", 9), undefined);
  assert.equal(requiredGpuMode("GB110 A01 GSP BROM", 0), undefined);
  assert.equal(requiredGpuMode("unknown", 1), undefined);
});
