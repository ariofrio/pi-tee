// SPDX-License-Identifier: Apache-2.0
// Adapted from virtee/sev-snp-measure 0.0.12 sevsnpmeasure/{guest,gctx,
// sev_hashes,vmsa}.py: SNP launch digest for QEMU, EPYC-v4 vCPUs and guest
// features 0x1, as Tinfoil's measurement action computes it. See THIRD_PARTY_LICENSES.
import { createHash } from "node:crypto";
import { TeeError } from "pi-tee-core";

// tinfoilsh/edk2 v0.0.3 OVMF.fd (SHA256 3a38d062…1c9f), authenticated by its
// release.yml@refs/tags/v0.0.3 attestation (commit 3b2f00a). The digest after
// measuring its pages and its parsed SEV metadata replace the 4 MiB image.
export const SNP_FIRMWARE = Object.freeze({
  ovmf: "3a38d062226a2369b1bd85b5408ed597eec793dad71c466f82f5765e4e7b1c9f",
  pageDigest: "c82d401c52d61e8ce0cee3367d80cefce1fd28aac3909195433f2773b0484d97470c4214a6c3e168c93e2219e0f92c69",
  hashesTableGpa: 0x810c00,
  resetEip: 0x80b004,
  // [gpa, size, type]: 1 zero, 2 secrets, 3 CPUID, 4 SVSM CAA (zero), 0x10 kernel hashes.
  sections: Object.freeze([[0x800000, 0x9000, 1], [0x80a000, 0x3000, 1], [0x80d000, 0x1000, 2], [0x80e000, 0x1000, 3],
    [0x80f000, 0x1000, 4], [0x811000, 0xf000, 1], [0x810000, 0x1000, 0x10]] as const),
  vcpuSignature: 0x800f12,
  guestFeatures: 1,
});

const sha384 = (bytes: Uint8Array) => createHash("sha384").update(bytes).digest();
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest();
function requireCondition(ok: unknown): asserts ok { if (!ok) throw new TeeError("TEE_BOOT_MEASUREMENT_REJECTED"); }

function guid(text: string) {
  const hex = Buffer.from(text.replaceAll("-", ""), "hex");
  return Buffer.concat([Buffer.from(hex.subarray(0, 4)).reverse(), Buffer.from(hex.subarray(4, 6)).reverse(), Buffer.from(hex.subarray(6, 8)).reverse(), hex.subarray(8)]);
}

// QEMU's SEV hashes table: header, then cmdline, initrd and kernel entries,
// padded to 16 bytes.
function hashesTable(kernel: Uint8Array, initrd: Uint8Array, command: string) {
  const entry = (id: string, hash: Buffer) => { const length = Buffer.alloc(2); length.writeUInt16LE(50); return Buffer.concat([guid(id), length, hash]); };
  const entries = Buffer.concat([
    entry("97d02dd8-bd20-4c94-aa78-e7714d36ab2a", sha256(Buffer.from(command + "\0"))),
    entry("44baf731-3a2f-4bd7-9af1-41e29169781d", sha256(initrd)),
    entry("4de79437-abd2-427f-b835-d5b172d2045b", sha256(kernel)),
  ]);
  const length = Buffer.alloc(2); length.writeUInt16LE(18 + entries.length);
  const table = Buffer.concat([guid("9438d606-4f22-4cc9-b479-a793d411fd21"), length, entries]);
  return Buffer.concat([table, Buffer.alloc(((table.length + 15) & ~15) - table.length)]);
}

function saveArea(eip: number) {
  const page = Buffer.alloc(4096);
  const segment = (offset: number, selector: number, attrib: number, limit: number, base: number) => {
    page.writeUInt16LE(selector, offset); page.writeUInt16LE(attrib, offset + 2);
    page.writeUInt32LE(limit, offset + 4); page.writeBigUInt64LE(BigInt(base), offset + 8);
  };
  segment(0x00, 0, 0x93, 0xffff, 0); // es
  segment(0x10, 0xf000, 0x9b, 0xffff, Number((BigInt(eip) & 0xffff0000n))); // cs
  for (const offset of [0x20, 0x30, 0x40, 0x50]) segment(offset, 0, 0x93, 0xffff, 0); // ss, ds, fs, gs
  segment(0x60, 0, 0, 0xffff, 0); // gdtr
  segment(0x70, 0, 0x82, 0xffff, 0); // ldtr
  segment(0x80, 0, 0, 0xffff, 0); // idtr
  segment(0x90, 0, 0x8b, 0xffff, 0); // tr
  const u64 = (offset: number, value: bigint) => page.writeBigUInt64LE(value, offset);
  u64(0xd0, 0x1000n); u64(0x148, 0x40n); u64(0x158, 0x10n); u64(0x160, 0x400n); u64(0x168, 0xffff0ff0n); // efer, cr4, cr0, dr7, dr6
  u64(0x170, 0x2n); u64(0x178, BigInt(eip & 0xffff)); u64(0x268, 0x7040600070406n); // rflags, rip, g_pat
  u64(0x310, BigInt(SNP_FIRMWARE.vcpuSignature)); u64(0x3b0, BigInt(SNP_FIRMWARE.guestFeatures)); u64(0x3e8, 1n); // rdx, sev_features, xcr0
  page.writeUInt32LE(0x1f80, 0x408); page.writeUInt16LE(0x37f, 0x410); // mxcsr, x87_fcw
  return page;
}

/** Recomputes a QEMU SEV-SNP launch digest for the pinned OVMF and direct kernel boot. */
export function computeSnpLaunchDigest(kernel: Buffer, initrd: Buffer, vcpus: number, command: string): string {
  requireCondition(kernel.length > 0 && kernel.length <= 32 * 1024 * 1024 && initrd.length <= 32 * 1024 * 1024);
  requireCondition(Number.isSafeInteger(vcpus) && vcpus >= 1 && vcpus <= 512 && typeof command === "string" && command.length <= 8192 && !command.includes("\0"));
  let digest: Buffer = Buffer.from(SNP_FIRMWARE.pageDigest, "hex");
  const update = (type: number, gpa: number, contents: Buffer) => {
    const info = Buffer.alloc(0x70);
    digest.copy(info, 0); contents.copy(info, 48);
    info.writeUInt16LE(0x70, 96); info[98] = type;
    info.writeBigUInt64LE(BigInt(gpa), 104);
    digest = sha384(info);
  };
  const zeros = Buffer.alloc(48);
  for (const [gpa, size, type] of SNP_FIRMWARE.sections) {
    if (type === 1 || type === 4) for (let offset = 0; offset < size; offset += 4096) update(3, gpa + offset, zeros);
    else if (type === 2) update(5, gpa, zeros);
    else if (type === 3) update(6, gpa, zeros);
    else {
      const page = Buffer.alloc(size);
      hashesTable(kernel, initrd, command).copy(page, SNP_FIRMWARE.hashesTableGpa & 0xfff);
      for (let offset = 0; offset < size; offset += 4096) update(1, gpa + offset, sha384(page.subarray(offset, offset + 4096)));
    }
  }
  const bsp = sha384(saveArea(0xfffffff0));
  const ap = sha384(saveArea(SNP_FIRMWARE.resetEip));
  for (let index = 0; index < vcpus; index++) update(2, 0xfffffffff000, index === 0 ? bsp : ap);
  return digest.toString("hex");
}
