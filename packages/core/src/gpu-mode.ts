import { TeeError } from "./policy.js";

// Field interpretation only. Callers must authenticate these exact bytes with
// NVIDIA's verifier before using the result for admission. NVIDIA nvtrust maps
// feature values 0/1/2 to SPT/MPT/PPCIe; the inspected C++ enum swaps 0 and 1.
// Python mapping: https://github.com/NVIDIA/nvtrust/blob/858ada9a17f58c482f578414ea2455498fa51e17/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/attestation/spdm_msrt_resp_msg.py#L365
export function parseHopperGpuMode(report: string): "spt" | "mpt" | "ppcie" {
  const reject = () => { throw new TeeError("TEE_GPU_MODE_REJECTED"); };
  if (typeof report !== "string" || report.length > 24 * 1024) return reject();
  const bytes = Buffer.from(report, "base64");
  if (bytes.toString("base64") !== report || bytes.length < 37 + 8 + 32 + 2 + 96 ||
    bytes[0] !== 0x11 || bytes[1] !== 0xe0 || bytes[37] !== 0x11 || bytes[38] !== 0x60 || !bytes[41]) return reject();
  const records = bytes.readUIntLE(42, 3);
  let offset = 37 + 8 + records + 32;
  if (records === 0 || offset + 2 + 96 > bytes.length) return reject();
  const size = bytes.readUInt16LE(offset); offset += 2;
  const end = offset + size;
  if (size === 0 || end + 96 !== bytes.length) return reject();
  const fields = new Map<number, Buffer>();
  while (offset < end) {
    if (offset + 4 > end) return reject();
    const type = bytes.readUInt16LE(offset), length = bytes.readUInt16LE(offset + 2);
    offset += 4;
    if (fields.has(type) || length === 0 || offset + length > end) return reject();
    fields.set(type, bytes.subarray(offset, offset + length));
    offset += length;
  }
  const integer = (type: number): bigint => {
    const field = fields.get(type);
    if (!field || field.length > 8) return reject();
    let value = 0n;
    for (let index = field.length - 1; index >= 0; index--) value = (value << 8n) | BigInt(field[index]!);
    return value;
  };
  if (integer(34) !== 1n) return reject();
  switch (integer(36)) {
    case 0n: return "spt";
    case 1n: return "mpt";
    case 2n: return "ppcie";
    default: return reject();
  }
}
