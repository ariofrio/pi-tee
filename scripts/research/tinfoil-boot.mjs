import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import assert from "node:assert/strict";

// Offline artifact trace, not a hardware verifier or an Approved decision.
const [directory, configPath] = process.argv.slice(2);
assert(directory && configPath, "usage: node tinfoil-boot.mjs ARTIFACT_DIRECTORY SOURCE_CONFIG");
const hash = (algorithm, bytes) => createHash(algorithm).update(bytes).digest();
const sha256 = bytes => hash("sha256", bytes).toString("hex");
const read = name => readFile(resolve(directory, name));
const artifact = await read("tinfoil-gemma-v0.0.25-deployment.json");
assert.equal(sha256(artifact), "65f2dfa59ced010aeba841fc909880ac3434282cf2b43e90d5c3a3e543b3ccf0", "deployment artifact digest");
const deployment = JSON.parse(artifact);
const sourceConfig = await readFile(configPath);
assert(Buffer.from(deployment.config, "base64").equals(sourceConfig), "deployment must contain the exact source config bytes");
assert.equal(sha256(sourceConfig), "1aeed2c83d17555fcffbf1f6ec82f0cefd22ea09d61b4b1385b5d1451ed706a4", "source config digest");
const expectedCommand = "readonly=on pci=realloc,nocrs modprobe.blacklist=nouveau nouveau.modeset=0 root=/dev/mapper/root roothash=6bf30dfe78f9646111afbc718e3a819d618981f453f31ecca8d4e166b9fc9dd9 tinfoil-config-hash=1aeed2c83d17555fcffbf1f6ec82f0cefd22ea09d61b4b1385b5d1451ed706a4";
assert.equal(deployment.cmdline, expectedCommand, "exact non-debug boot command line");
const kernel = await read("tinfoil-inference-v0.11.0.vmlinuz");
const initrd = await read("tinfoil-inference-v0.11.0.initrd");
assert.equal(sha256(kernel), "b1e042ac790ffbd1f8031d13e870f7b907d2bf685e755d43b2975c78752b42eb", "kernel digest");
assert.equal(sha256(initrd), "fc1d0b7a6703e1b6c7dd34113aea3c3f5f5ef51decb3363736103c46efc9a24d", "initrd digest");

// Direct-boot RTMR2: extend UTF-16LE NUL-terminated command line, then initrd.
// OVMF appends " initrd=initrd" before measuring the command line.
const commandBytes = Buffer.from(`${expectedCommand} initrd=initrd\0`, "utf16le");
let rtmr2 = Buffer.alloc(48);
for (const bytes of [commandBytes, initrd]) {
  rtmr2 = hash("sha384", Buffer.concat([rtmr2, hash("sha384", bytes)]));
}
const policy = JSON.parse(await readFile(new URL("../../tools/tinfoil-cpu/tdx.json", import.meta.url)));
assert.equal(rtmr2.toString("hex"), policy.registers[3], "recomputed RTMR2 must match the local CPU policy");
assert.equal(deployment.tdx_measurement.rtmr2, policy.registers[3], "deployment RTMR2 must match the local CPU policy");
console.log(JSON.stringify({
  deploymentDigestMatched: true, sourceConfigBytesMatched: true,
  kernelDigestMatched: true, initrdDigestMatched: true,
  rtmr2Recomputed: rtmr2.toString("hex"),
  independentRebuild: false, independentApproval: false,
}));
