// Version floors supplement manufacturer signatures, reference matching and
// revocation; NVIDIA revokes references for vulnerable firmware through OCSP.
// Each floor is the oldest version seen with signed, unrevoked references when
// the model was qualified (2026-10-07). They are not a firmware security rank.
// Each NVIDIA hardware model has its own VBIOS numbering; the protected mode
// required depends on how many GPUs the CVM uses.
export const GPU_POLICIES = Object.freeze({
  // Hopper multi-GPU confidential computing (PPCIe) also needs NVSwitch
  // attestation, which Tinfoil's evidence does not carry.
  "GH100 A01 GSP BROM": Object.freeze({ arch: "HOPPER", driver: "595.71.05", vbios: "96.00.D0.00.03", maxGpus: 1 }),
  // Blackwell MPT protects CPU-GPU transfers and peer NVLink for up to eight
  // GPUs; NVSwitches are outside its trusted computing base.
  "GB100 A01 GSP BROM": Object.freeze({ arch: "BLACKWELL", driver: "595.71.05", vbios: "97.00.D9.00.35", maxGpus: 8 }),
  "GB110 A01 GSP BROM": Object.freeze({ arch: "BLACKWELL", driver: "595.71.05", vbios: "97.10.64.00.0C", maxGpus: 8 }),
});
export type GpuModel = keyof typeof GPU_POLICIES;

function atLeast(value: number[], floor: number[]): boolean {
  for (let index = 0; index < floor.length; index++) {
    if (value[index] !== floor[index]) return value[index]! > floor[index]!;
  }
  return true;
}
const driverParts = (value: string) => value.split(".").map(Number);
const vbiosParts = (value: string) => value.split(".").map(part => Number.parseInt(part, 16));

export function gpuPolicy(hwmodel: unknown) {
  return typeof hwmodel === "string" && Object.hasOwn(GPU_POLICIES, hwmodel) ? GPU_POLICIES[hwmodel as GpuModel] : undefined;
}

export function gpuVersionsAllowed(hwmodel: unknown, driver: unknown, vbios: unknown): boolean {
  const policy = gpuPolicy(hwmodel);
  if (!policy || typeof driver !== "string" || typeof vbios !== "string" ||
      !/^[1-9][0-9]{2,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(driver) || !/^[a-fA-F0-9]{2}(\.[a-fA-F0-9]{2}){4}$/.test(vbios)) return false;
  return atLeast(driverParts(driver), driverParts(policy.driver)) && atLeast(vbiosParts(vbios), vbiosParts(policy.vbios));
}

/** The authenticated protected mode each GPU must report for a CVM with `count` GPUs. */
export function requiredGpuMode(hwmodel: unknown, count: number): "spt" | "mpt" | undefined {
  const policy = gpuPolicy(hwmodel);
  if (!policy || !Number.isSafeInteger(count) || count < 1 || count > policy.maxGpus) return undefined;
  return count === 1 ? "spt" : "mpt";
}
