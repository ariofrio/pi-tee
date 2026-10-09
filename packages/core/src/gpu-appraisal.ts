import { parseHopperGpuMode } from "./gpu-mode.js";
import { TeeError } from "./policy.js";

/**
 * One NVIDIA hardware model's admission rule. Version floors supplement
 * manufacturer signatures, reference matching and revocation; they are not a
 * firmware security rank. A CVM with one GPU must report SPT; with more, each
 * GPU must report `multiGpuMode` (MPT unless stated).
 */
export type GpuPolicy = Readonly<{ arch: string; driver: string; vbios: string; maxGpus: number; multiGpuMode?: "mpt" | "ppcie" }>;
export type GpuPolicyTable = Readonly<Record<string, GpuPolicy>>;

// Version floors supplement manufacturer signatures, reference matching and
// revocation; NVIDIA revokes references for vulnerable firmware through OCSP.
// Each floor is the oldest version seen with signed, unrevoked references when
// the model was qualified (2026-10-07). They are not a firmware security rank.
// Each NVIDIA hardware model has its own VBIOS numbering; the protected mode
// required depends on how many GPUs the CVM uses.
/** The default GPU policy, qualified for Tinfoil's public profile. Providers fail closed on anything it does not admit. */
export const GPU_POLICIES = Object.freeze({
  // Hopper multi-GPU confidential computing (PPCIe) also needs NVSwitch
  // attestation, which neither provider's evidence carries.
  "GH100 A01 GSP BROM": Object.freeze({ arch: "HOPPER", driver: "595.71.05", vbios: "96.00.D0.00.03", maxGpus: 1 }),
  // Blackwell MPT protects CPU-GPU transfers and peer NVLink for up to eight
  // GPUs; NVSwitches are outside its trusted computing base.
  "GB100 A01 GSP BROM": Object.freeze({ arch: "BLACKWELL", driver: "595.71.05", vbios: "97.00.D9.00.35", maxGpus: 8 }),
  "GB110 A01 GSP BROM": Object.freeze({ arch: "BLACKWELL", driver: "595.71.05", vbios: "97.10.64.00.0C", maxGpus: 8 }),
});
export const REQUIRED_CLAIMS = Object.freeze([
  "x-nvidia-gpu-arch-check", "x-nvidia-gpu-attestation-report-parsed", "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
  "x-nvidia-gpu-driver-rim-fetched", "x-nvidia-gpu-driver-rim-measurements-available", "x-nvidia-gpu-driver-rim-signature-verified",
  "x-nvidia-gpu-driver-rim-version-match", "x-nvidia-gpu-vbios-rim-fetched", "x-nvidia-gpu-vbios-rim-measurements-available",
  "x-nvidia-gpu-vbios-rim-signature-verified", "x-nvidia-gpu-vbios-rim-version-match", "x-nvidia-gpu-vbios-index-no-conflict",
  "x-nvidia-gpu-attestation-report-signature-verified", "x-nvidia-gpu-attestation-report-nonce-match",
]);
export const CERTIFICATE_CHAINS = Object.freeze(["x-nvidia-gpu-attestation-report-cert-chain", "x-nvidia-gpu-driver-rim-cert-chain", "x-nvidia-gpu-vbios-rim-cert-chain"]);

function atLeast(value: number[], floor: number[]): boolean {
  for (let index = 0; index < floor.length; index++) {
    if (value[index] !== floor[index]) return value[index]! > floor[index]!;
  }
  return true;
}
const driverParts = (value: string) => value.split(".").map(Number);
const vbiosParts = (value: string) => value.split(".").map(part => Number.parseInt(part, 16));

export function gpuPolicy(table: GpuPolicyTable, hwmodel: unknown) {
  return typeof hwmodel === "string" && Object.hasOwn(table, hwmodel) ? table[hwmodel] : undefined;
}

export function gpuVersionsAllowed(table: GpuPolicyTable, hwmodel: unknown, driver: unknown, vbios: unknown): boolean {
  const policy = gpuPolicy(table, hwmodel);
  if (!policy || typeof driver !== "string" || typeof vbios !== "string" ||
      !/^[1-9][0-9]{2,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(driver) || !/^[a-fA-F0-9]{2}(\.[a-fA-F0-9]{2}){4}$/.test(vbios)) return false;
  return atLeast(driverParts(driver), driverParts(policy.driver)) && atLeast(vbiosParts(vbios), vbiosParts(policy.vbios));
}

/** The authenticated protected mode each GPU must report for a CVM with `count` GPUs. */
export function requiredGpuMode(table: GpuPolicyTable, hwmodel: unknown, count: number): "spt" | "mpt" | "ppcie" | undefined {
  const policy = gpuPolicy(table, hwmodel);
  if (!policy || !Number.isSafeInteger(count) || count < 1 || count > policy.maxGpus) return undefined;
  return count === 1 ? "spt" : policy.multiGpuMode ?? "mpt";
}

function requireCondition(ok: unknown, code: string): asserts ok { if (!ok) throw new TeeError(code); }

/**
 * Applies a GPU policy to NVIDIA's local verdict for every report: one claim
 * per device, all the same supported model, distinct devices, signed
 * references and revocation checks, version floors and the required mode.
 */
export function checkGpuAppraisal(table: GpuPolicyTable, checked: { code: number; stdout: string }, evidence: { arch?: unknown; evidence?: unknown }[], nonce: string, count: number) {
  let gpu: any;
  try { gpu = JSON.parse(checked.stdout); } catch { throw new TeeError("TEE_GPU_POLICY_REJECTED"); }
  requireCondition(checked.code === 0 && gpu.result_code === 0 && Array.isArray(gpu.claims) && gpu.claims.length === count && evidence.length === count, "TEE_GPU_POLICY_REJECTED");
  const hwmodel = gpu.claims[0]?.hwmodel;
  const arch = gpuPolicy(table, hwmodel)?.arch;
  const mode = requiredGpuMode(table, hwmodel, count);
  requireCondition(arch && mode, "TEE_GPU_POLICY_REJECTED");
  const devicesSeen = new Set<string>();
  gpu.claims.forEach((c: any, index: number) => {
    requireCondition(c.eat_nonce === nonce && c.hwmodel === hwmodel && evidence[index]!.arch === arch && c.measres === "success" &&
      c.dbgstat === "disabled" && c.secboot === true && typeof c.ueid === "string" && !devicesSeen.has(c.ueid) &&
      gpuVersionsAllowed(table, c.hwmodel, c["x-nvidia-gpu-driver-version"], c["x-nvidia-gpu-vbios-version"]), "TEE_GPU_POLICY_REJECTED");
    devicesSeen.add(c.ueid);
    for (const field of REQUIRED_CLAIMS) requireCondition(c[field] === true, "TEE_GPU_POLICY_REJECTED");
    for (const field of CERTIFICATE_CHAINS) {
      const chain = c[field];
      requireCondition(chain?.["x-nvidia-cert-status"] === "valid" && chain["x-nvidia-cert-ocsp-status"] === "good" &&
        chain["x-nvidia-cert-ocsp-response-valid"] === true && chain["x-nvidia-cert-ocsp-nonce-matches"] === true, "TEE_GPU_POLICY_REJECTED");
    }
    // NVIDIA's verifier authenticated the report bytes carrying this field.
    requireCondition(parseHopperGpuMode(evidence[index]!.evidence as string) === mode, "TEE_GPU_MODE_REJECTED");
  });
}

/** Rates authenticated reports; incomplete serving coverage cannot establish G1 or G2. */
export function rateGpuAppraisal(table: GpuPolicyTable, checked: { code: number; stdout: string }, evidence: { arch?: unknown; evidence?: unknown }[], nonce: string, count: number,
  binding: { cpuFresh: boolean; completeCoverage: boolean; cpuHash: boolean }): { gpu: 1 | 2 | 3; observed: string[] } {
  if (!binding.cpuFresh || !binding.completeCoverage) return { gpu: 3, observed: [!binding.cpuFresh ? "GPU reports lack a fresh CPU commitment." : "GPU evidence does not establish serving coverage."] };
  const observed: string[] = binding.cpuHash ? [] : ["GPU association with the CPU is by shared nonce only."];
  try {
    checkGpuAppraisal(table, checked, evidence, nonce, count);
    return { gpu: binding.cpuHash ? 1 : 2, observed };
  } catch { /* Test the authenticated, fresh baseline without local firmware floors. */ }
  const baseline = Object.fromEntries(Object.entries(table).map(([model, rule]) => [model, {
    ...rule, driver: "0.0.0", vbios: "00.00.00.00.00", maxGpus: 8,
    ...(rule.arch === "HOPPER" ? { multiGpuMode: "ppcie" as const } : {}),
  }]));
  try {
    checkGpuAppraisal(baseline, checked, evidence, nonce, count);
    const claims = JSON.parse(checked.stdout).claims;
    if (claims.some((c: any) => !gpuVersionsAllowed(table, c.hwmodel, c["x-nvidia-gpu-driver-version"], c["x-nvidia-gpu-vbios-version"])))
      observed.push("Authenticated GPU firmware is below pi-tee's local floors.");
    if (count > 1 && baseline[claims[0].hwmodel]?.arch === "HOPPER") observed.push("Hopper PPCIe uses unattested NVSwitches.");
    return { gpu: 2, observed };
  } catch {
    return { gpu: 3, observed: ["Complete authenticated, fresh confidential GPU evidence was not established."] };
  }
}
