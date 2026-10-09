import { checkGpuAppraisal, GPU_POLICIES, runNvidiaVerifier, TeeError, type GpuPolicyTable } from "pi-tee-core";

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
