import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, mkdir, mkdtemp, writeFile, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";

const cli = (input: unknown) => spawnSync(process.execPath, ["--import", "tsx", "scripts/research/tinfoil-boot-measurements.ts"], { input: JSON.stringify(input), encoding: "utf8", timeout: 10000 });

test("the boot-measurement CLI rejects malformed artifact descriptors without authenticating a build", () => {
  const result = cli({ memoryMB: 65536, cmdline: "synthetic", kernel: "", initrd: "" });
  assert.equal(result.status, 1);
  const output = JSON.parse(result.stdout);
  assert.equal(output.failure, "TEE_BOOT_MEASUREMENT_REJECTED");
  assert.equal(output.authenticatedBuild, false);
  assert.equal(output.inferenceQualified, false);
});

test("the boot-measurement CLI matches real release registers and detects altered code or command bytes", { skip: !process.env.PI_TEE_BOOT_TEST_DIR }, async () => {
  const directory = process.env.PI_TEE_BOOT_TEST_DIR!;
  const deployment = JSON.parse(await readFile("tools/tinfoil-public-build/testdata/gemma-v0.0.25-deployment.json", "utf8"));
  const input = { memoryMB: 65536, cmdline: deployment.cmdline,
    kernel: resolve(directory, "tinfoil-inference-v0.11.0.vmlinuz"), initrd: resolve(directory, "tinfoil-inference-v0.11.0.initrd") };
  const result = cli(input);
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.rtmr1, deployment.tdx_measurement.rtmr1);
  assert.equal(output.rtmr2, deployment.tdx_measurement.rtmr2);
  assert.equal(output.authenticatedBuild, false);
  assert.equal(output.inferenceQualified, false);
  const changedCommand = JSON.parse(cli({ ...input, cmdline: input.cmdline + " debug=1" }).stdout);
  assert.notEqual(changedCommand.rtmr2, output.rtmr2);
  await mkdir(".scratch/work", { recursive: true });
  const scratch = await mkdtemp(resolve(".scratch/work/boot-code-"));
  try {
    const code = await readFile(input.kernel);
    code[0x10000] = code[0x10000]! ^ 1;
    const path = resolve(scratch, "kernel");
    await writeFile(path, code);
    const changed = cli({ ...input, kernel: path });
    assert.equal(changed.status, 0, changed.stderr);
    assert.notEqual(JSON.parse(changed.stdout).rtmr1, output.rtmr1);
    const original = await readFile(input.kernel);
    const pe = original.readUInt32LE(0x3c), optional = pe + 24;
    for (const mutation of [
      (bytes: Buffer) => bytes.writeUInt32LE(0xffffffff, 0x3c),
      (bytes: Buffer) => bytes.writeUInt16LE(0xffff, pe + 6),
      (bytes: Buffer) => bytes.writeUInt16LE(0x10b, optional),
      (bytes: Buffer) => bytes.writeUInt32LE(0xffffffff, optional + 60),
      (bytes: Buffer) => bytes.writeUInt32LE(16, optional + 112 + 4 * 8),
      (bytes: Buffer) => bytes.writeUInt32LE(0, optional + original.readUInt16LE(pe + 20) + 20),
    ]) {
      const invalid = Buffer.from(original);
      mutation(invalid);
      await writeFile(path, invalid);
      const rejected = cli({ ...input, kernel: path });
      assert.equal(rejected.status, 1, "Unsupported PE layout must fail closed.");
      assert.equal(JSON.parse(rejected.stdout).failure, "TEE_BOOT_MEASUREMENT_REJECTED");
    }
  } finally { await rm(scratch, { recursive: true, force: true }); }
});
