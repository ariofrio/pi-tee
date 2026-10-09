import { gpuVersionsAllowed, checkGpuAppraisal, GPU_POLICIES, runNvidiaVerifier, TeeError, type GpuPolicyTable } from "pi-tee-core";
import type { ModelAttestationPolicy, ModelAttestationVerifiers, TdxQuoteVerifier } from "@nearai/inference-sdk/node";

const MAX_PAYLOAD_CHARACTERS = 2 * 1024 * 1024;
const MAX_GPUS = 8;
type Runner = (options: { evidence: unknown[]; nonce: string; signal: AbortSignal }) => Promise<{ code: number; stdout: string }>;

/**
 * Appraises one attestation's `nvidia_payload` with NVIDIA's local verifier
 * and a GPU policy table, by default the shared one Tinfoil is qualified
 * against. The SDK has already required the payload nonce to equal the
 * client's fresh nonce; every signed GPU report must carry it too. Nothing in
 * NEAR's quote attests how many GPUs the CVM uses: the policy judges the
 * reports presented.
 */
export async function checkNearGpuEvidence(payload: string, options: { signal: AbortSignal; policy?: GpuPolicyTable; run?: Runner }) {
  const reject = (): never => { throw new TeeError("TEE_GPU_POLICY_REJECTED"); };
  if (typeof payload !== "string" || payload.length > MAX_PAYLOAD_CHARACTERS) reject();
  let parsed: any;
  try { parsed = JSON.parse(payload); } catch { reject(); }
  const nonce = parsed?.nonce;
  const items: unknown = parsed?.evidence_list;
  if (!parsed || typeof parsed !== "object" || Object.keys(parsed).sort().join() !== "arch,evidence_list,nonce" ||
      typeof nonce !== "string" || !/^[a-f0-9]{64}$/.test(nonce) || !Array.isArray(items) || items.length < 1 || items.length > MAX_GPUS) reject();
  const evidence = (items as any[]).map(item => {
    if (!item || typeof item !== "object" || Object.keys(item).sort().join() !== "arch,certificate,evidence,nonce" || item.nonce !== nonce ||
        item.arch !== parsed.arch || typeof item.certificate !== "string" || typeof item.evidence !== "string") reject();
    return { arch: item.arch, certificate: item.certificate, evidence: item.evidence, nonce: item.nonce };
  });
  const checked = await (options.run ?? runNvidiaVerifier)({ evidence, nonce, signal: options.signal });
  checkGpuAppraisal(options.policy ?? GPU_POLICIES, checked, evidence, nonce, evidence.length);
}

/** Optional, local status details. Coverage is unknown, so these cannot upgrade NEAR above G3. */
export async function observeNearGpuEvidence(payload: string, nonce: string, options: { signal: AbortSignal; run?: Runner }): Promise<string[]> {
  try {
    const parsed = JSON.parse(payload);
    if (parsed.nonce !== nonce) throw new TeeError("TEE_GPU_POLICY_REJECTED");
    const table = Object.fromEntries(Object.entries(GPU_POLICIES).map(([name, rule]) => [name, { ...rule,
      driver: "0.0.0", vbios: "00.00.00.00.00", maxGpus: 8,
      ...(rule.arch === "HOPPER" ? { multiGpuMode: "ppcie" as const } : {}),
    }]));
    let result: Awaited<ReturnType<Runner>> | undefined;
    await checkNearGpuEvidence(payload, { signal: options.signal, policy: table, run: async request => {
      result = await (options.run ?? runNvidiaVerifier)(request);
      return result;
    } });
    const claims = JSON.parse(result!.stdout).claims as Record<string, any>[];
    const observed = ["Reported GPUs are not shown to be all GPUs serving the request", "GPU–CPU association uses the shared nonce only"];
    if (parsed.arch === "HOPPER" && claims.length > 1) observed.push("Hopper PPCIe with unattested NVSwitches");
    for (const c of claims) {
      const driver = c["x-nvidia-gpu-driver-version"], vbios = c["x-nvidia-gpu-vbios-version"];
      observed.push(`Authenticated reported GPU ${c.hwmodel}: driver ${driver}, VBIOS ${vbios}`);
      const floor = GPU_POLICIES[c.hwmodel as keyof typeof GPU_POLICIES];
      if (floor && !gpuVersionsAllowed(GPU_POLICIES, c.hwmodel, driver, vbios)) observed.push("Reported GPU firmware is below pi-tee's local floors");
      if (typeof driver === "string" && driver.startsWith("570.")) observed.push("GPU driver branch R570 has no fix in NVIDIA's May 2026 bulletin");
    }
    return [...new Set(observed)];
  } catch {
    options.signal.throwIfAborted();
    return ["Local GPU detail appraisal did not establish authenticated device details; route remains G3"];
  }
}

/**
 * Model verification for both NEAR routes. They strip GPU payloads before SDK
 * appraisal; the SDK's default GPU verifier would submit any that still reach
 * it to NRAS, so this one rejects them locally instead.
 */
export function nearModelVerification(tdxQuote: TdxQuoteVerifier): { policy: ModelAttestationPolicy; verifiers: ModelAttestationVerifiers } {
  return {
    policy: { acceptedTcbStatuses: ["UpToDate", "OutOfDate"], gpuEvidence: "if-present" },
    verifiers: { tdxQuote, gpuEvidence: () => { throw new TeeError("TEE_GPU_POLICY_REJECTED"); } },
  };
}
