import * as core from "pi-tee-core";
import { GPU_POLICIES } from "pi-tee-core";

// The shared default GPU policy; Tinfoil's public profile is qualified against it.
export { GPU_POLICIES };
export type GpuModel = keyof typeof GPU_POLICIES;

export const gpuPolicy = (hwmodel: unknown) => core.gpuPolicy(GPU_POLICIES, hwmodel);
export const gpuVersionsAllowed = (hwmodel: unknown, driver: unknown, vbios: unknown) => core.gpuVersionsAllowed(GPU_POLICIES, hwmodel, driver, vbios);
/** The authenticated protected mode each GPU must report for a CVM with `count` GPUs. */
export const requiredGpuMode = (hwmodel: unknown, count: number) => core.requiredGpuMode(GPU_POLICIES, hwmodel, count);
