import * as core from "pi-tee-core";

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

export const gpuPolicy = (hwmodel: unknown) => core.gpuPolicy(GPU_POLICIES, hwmodel);
export const gpuVersionsAllowed = (hwmodel: unknown, driver: unknown, vbios: unknown) => core.gpuVersionsAllowed(GPU_POLICIES, hwmodel, driver, vbios);
/** The authenticated protected mode each GPU must report for a CVM with `count` GPUs. */
export const requiredGpuMode = (hwmodel: unknown, count: number) => core.requiredGpuMode(GPU_POLICIES, hwmodel, count);
