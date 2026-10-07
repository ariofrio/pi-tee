// SPDX-License-Identifier: Apache-2.0
// Adapted from tinfoilsh/tdx-measure 9311cb9bdf3f83c9e3ec8dae4b6dff78a6d46123
// src/kernel.rs and src/util.rs. TypeScript port with stricter size/layout checks;
// unsigned contiguous AMD64 PE32+ kernels only. See THIRD_PARTY_LICENSES.
import { createHash } from "node:crypto";
import { TeeError } from "pi-tee-core";

const digest = (bytes: Uint8Array) => createHash("sha384").update(bytes).digest();
function requireCondition(ok: unknown): asserts ok { if (!ok) throw new TeeError("TEE_BOOT_MEASUREMENT_REJECTED"); }
function extend(events: Uint8Array[]): string {
  let register: Buffer = Buffer.alloc(48);
  for (const event of events) register = digest(Buffer.concat([register, event]));
  return register.toString("hex");
}

export function computeBootMeasurements(kernel: Buffer, initrd: Buffer, memoryMB: number, command: string) {
  requireCondition(kernel.length >= 0x1000 && kernel.length <= 32 * 1024 * 1024 && initrd.length > 0 && initrd.length <= 32 * 1024 * 1024);
  requireCondition(Number.isSafeInteger(memoryMB) && memoryMB >= 1 && memoryMB <= 0x100000 && typeof command === "string" && command.length <= 8192 && !command.includes("\0"));
  const patched = Buffer.from(kernel);
  const protocol = patched.readUInt16LE(0x206);
  requireCondition(protocol >= 0x200);
  const modern = (patched[0x211]! & 1) !== 0;
  const realAddress = modern ? 0x10000 : 0x90000;
  const commandAddress = modern ? 0x20000 : 0x9a000;
  patched[0x210] = 0xb0;
  if (protocol >= 0x201) {
    patched[0x211] = patched[0x211]! | 0x80;
    // Preserve the authenticated producer's four-byte write, including padding.
    patched.writeUInt32LE(commandAddress - realAddress - 0x200, 0x224);
  }
  if (protocol >= 0x202) patched.writeUInt32LE(commandAddress, 0x228);
  else { patched.writeUInt16LE(0xa33f, 0x20); patched.writeUInt16LE(commandAddress - realAddress, 0x22); }
  let initrdMaximum = 0x37ffffff;
  if (protocol >= 0x20c) initrdMaximum = (patched.readUInt16LE(0x236) & 0x40) !== 0 ? 0xffffffff : initrdMaximum;
  else if (protocol >= 0x203) initrdMaximum = patched.readUInt32LE(0x22c) || initrdMaximum;
  // The release producer passes its MB numeric value with a G suffix. This
  // reproduces that calculation; the independent signed shape check uses MB.
  const producerMemory = BigInt(memoryMB) * (1n << 30n);
  const lowMemory = producerMemory < 0xb0000000n ? 0xb0000000n : 0x80000000n;
  const below4G = Number(producerMemory >= lowMemory ? lowMemory : producerMemory);
  const acpiBytes = 0x28000;
  requireCondition(below4G > acpiBytes);
  if (initrdMaximum >= below4G - acpiBytes) initrdMaximum = below4G - acpiBytes - 1;
  requireCondition(initrd.length < initrdMaximum);
  patched.writeUInt32LE(Math.floor((initrdMaximum - initrd.length) / 4096) * 4096, 0x218);
  patched.writeUInt32LE(initrd.length, 0x21c);

  function u16(offset: number) { requireCondition(offset >= 0 && offset + 2 <= patched.length); return patched.readUInt16LE(offset); }
  function u32(offset: number) { requireCondition(offset >= 0 && offset + 4 <= patched.length); return patched.readUInt32LE(offset); }
  const pe = u32(0x3c);
  requireCondition(u16(0) === 0x5a4d && u32(pe) === 0x4550 && u16(pe + 4) === 0x8664);
  const coff = pe + 4, optional = coff + 20;
  requireCondition(u16(optional) === 0x20b && u32(optional + 108) >= 5);
  const optionalSize = u16(coff + 16);
  const checksum = optional + 64, certificate = optional + 112 + 4 * 8;
  const headers = u32(optional + 60);
  requireCondition(optionalSize >= 152 && certificate + 8 <= optional + optionalSize && headers <= patched.length && headers >= certificate + 8);
  requireCondition(u32(certificate) === 0 && u32(certificate + 4) === 0);
  const count = u16(coff + 2), table = optional + optionalSize;
  requireCondition(count >= 1 && count <= 96 && table + count * 40 <= headers);
  const sections: { offset: number; size: number }[] = [];
  for (let n = 0; n < count; n++) {
    const section = table + n * 40;
    const size = u32(section + 16), offset = u32(section + 20);
    if (size > 0) { requireCondition(offset >= headers && offset + size <= patched.length); sections.push({ offset, size }); }
  }
  sections.sort((a, b) => a.offset - b.offset);
  let end = headers;
  for (const section of sections) { requireCondition(section.offset === end); end += section.size; }
  requireCondition(end === patched.length);
  const hash = createHash("sha384");
  hash.update(patched.subarray(0, checksum));
  hash.update(patched.subarray(checksum + 4, certificate));
  hash.update(patched.subarray(certificate + 8, headers));
  for (const section of sections) hash.update(patched.subarray(section.offset, section.offset + section.size));
  if (patched.length % 8) hash.update(Buffer.alloc(8 - patched.length % 8));
  const rtmr1 = extend([
    hash.digest(), digest(Buffer.from("Calling EFI Application from Boot Option")), digest(Buffer.alloc(4)),
    digest(Buffer.from("Exit Boot Services Invocation")), digest(Buffer.from("Exit Boot Services Returned with Success")),
  ]);
  const rtmr2 = extend([digest(Buffer.from(`${command} initrd=initrd\0`, "utf16le")), digest(initrd)]);
  return { bootMeasurementsComputed: true, rtmr1, rtmr2, authenticatedBuild: false, inferenceQualified: false };
}
