import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

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
