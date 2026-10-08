import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { computeSnpLaunchDigest } from "../packages/tinfoil/src/snp-measurement.js";

// Expected digests come from sev-snp-measure 0.0.12 with tinfoilsh/edk2 v0.0.3
// OVMF.fd, the inputs Tinfoil's measurement action uses, on synthetic boot bytes.
const kernel = Buffer.from("kernel-".repeat(1000));
const initrd = Buffer.from("initrd-".repeat(777));

test("the SEV-SNP launch digest matches the reference calculator", () => {
  for (const [vcpus, command, expected] of [
    [1, "console=null", "d6c99d986822fa7fdfb460251e244c4e78a2bdd986e937ee4d92fac675540e1099e501ecc340220e1e8d6d6f0512d51b"],
    [16, "readonly=on root=/dev/mapper/root", "840907cf23aadb95afbe493db666afff28b6223ddce8b597d97fac35a85193090894e7193579e36892b26b9446a3ecdb"],
    [32, "a b c", "a54c71d36c33d7a6d07e8a365c21349069f142872edbe2c4d78ccde71720d09b5283aa46e54373423e57e143f15e86d9"],
  ] as const) {
    assert.equal(computeSnpLaunchDigest(kernel, initrd, vcpus, command), expected);
  }
});

test("the SEV-SNP launch digest binds kernel, initrd, command line and vCPU count", () => {
  const base = computeSnpLaunchDigest(kernel, initrd, 16, "a");
  const changedKernel = Buffer.from(kernel); changedKernel[0]! ^= 1;
  for (const changed of [
    computeSnpLaunchDigest(changedKernel, initrd, 16, "a"),
    computeSnpLaunchDigest(kernel, Buffer.concat([initrd, Buffer.from([0])]), 16, "a"),
    computeSnpLaunchDigest(kernel, initrd, 16, "a debug"),
    computeSnpLaunchDigest(kernel, initrd, 15, "a"),
  ]) assert.notEqual(changed, base);
});

test("the SEV-SNP launch digest rejects malformed inputs", () => {
  for (const [k, i, vcpus, command] of [
    [Buffer.alloc(0), initrd, 1, "a"], [kernel, initrd, 0, "a"], [kernel, initrd, 1.5, "a"], [kernel, initrd, 513, "a"],
    [kernel, initrd, 1, "a\0b"], [kernel, initrd, 1, "a".repeat(8193)],
  ] as const) {
    assert.throws(() => computeSnpLaunchDigest(k, i, vcpus, command), /TEE_BOOT_MEASUREMENT_REJECTED/);
  }
});

test("the SEV-SNP launch digest matches every public release's signed measurement", { skip: !process.env.PI_TEE_BOOT_TEST_DIR }, async () => {
  const directory = process.env.PI_TEE_BOOT_TEST_DIR!;
  for (const name of ["gemma-v0.0.25", "glm53-v0.0.3", "deepseek-v0.0.3"]) {
    const deployment = JSON.parse(await readFile(`tools/tinfoil-public-build/testdata/${name}-deployment.json`, "utf8"));
    const version = deployment.hashes.version;
    const [k, i] = await Promise.all([
      readFile(resolve(directory, `tinfoil-inference-${version}.vmlinuz`)), readFile(resolve(directory, `tinfoil-inference-${version}.initrd`)),
    ]);
    assert.equal(computeSnpLaunchDigest(k, i, deployment.vm_shape.cpus, deployment.cmdline), deployment.snp_measurement, name);
  }
});
