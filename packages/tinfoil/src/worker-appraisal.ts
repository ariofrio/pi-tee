import { randomBytes } from "node:crypto";
import { TeeError, readBoundedBody } from "pi-tee-core";
import { parseHopperGpuMode } from "./gpu-mode.js";
import { gpuPolicy, gpuVersionsAllowed, requiredGpuMode } from "./gpu-policy.js";
import { verifyPublicBuildArtifacts } from "./public-build.js";
import { runNvidiaVerifier } from "./wasm-verifiers.js";

/** Models admitted under public builds and the one publisher repository for each. */
export const PUBLIC_MODELS = Object.freeze({
  "gemma4-31b": "tinfoilsh/confidential-gemma4-31b",
  "deepseek-v4-1-flash": "tinfoilsh/confidential-deepseek-v4-1-flash",
  "glm-5-3": "tinfoilsh/confidential-glm5-3-nvfp4",
});
export type PublicModel = keyof typeof PUBLIC_MODELS;
export const WORKER_HOST = /^[a-z0-9-]+-inf[0-9]+(?:-[0-9]+)?\.tinfoil\.containers\.tinfoil\.dev$/;

const REQUIRED_CLAIMS = [
  "x-nvidia-gpu-arch-check", "x-nvidia-gpu-attestation-report-parsed", "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
  "x-nvidia-gpu-driver-rim-fetched", "x-nvidia-gpu-driver-rim-measurements-available", "x-nvidia-gpu-driver-rim-signature-verified",
  "x-nvidia-gpu-driver-rim-version-match", "x-nvidia-gpu-vbios-rim-fetched", "x-nvidia-gpu-vbios-rim-measurements-available",
  "x-nvidia-gpu-vbios-rim-signature-verified", "x-nvidia-gpu-vbios-rim-version-match", "x-nvidia-gpu-vbios-index-no-conflict",
  "x-nvidia-gpu-attestation-report-signature-verified", "x-nvidia-gpu-attestation-report-nonce-match",
];
const CERTIFICATE_CHAINS = ["x-nvidia-gpu-attestation-report-cert-chain", "x-nvidia-gpu-driver-rim-cert-chain", "x-nvidia-gpu-vbios-rim-cert-chain"];

function requireCondition(ok: unknown, code: string): asserts ok { if (!ok) throw new TeeError(code); }

/**
 * Fresh public-build appraisal of one worker: CPU quote, release, guest,
 * container and runtime chain, then every CPU-bound GPU report. Returns the
 * quote-bound endpoint keys only after all of it passes.
 */
export async function appraiseWorker(options: {
  model: PublicModel; host: string; signal: AbortSignal; evidenceFetch?: typeof globalThis.fetch; nvidiaCollateralOrigin?: string;
}): Promise<{ tls: string; hpke: string; publicBuild: {
  checkedAt: number; expiresAt: number; workloadDigest: string; platformDigest: string;
  cvmManifestDigest: string; imageDigest: string; configDigest: string; platform: "tdx" | "sev-snp"; gpus: number;
} }> {
  const repo = PUBLIC_MODELS[options.model];
  requireCondition(repo && WORKER_HOST.test(options.host), "TEE_REQUEST_REJECTED");
  const challengeAt = Date.now();
  const signal = AbortSignal.any([options.signal, AbortSignal.timeout(240000)]);
  signal.throwIfAborted();
  const nonce = randomBytes(32).toString("hex");
  const response = await (options.evidenceFetch ?? globalThis.fetch)(`https://${options.host}/.well-known/tinfoil-attestation?nonce=${nonce}`, { signal, redirect: "error" });
  requireCondition(response.ok, "TEE_ATTESTATION_REJECTED");
  const raw = new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(response.body, 2 * 1024 * 1024, signal));
  const envelope = JSON.parse(raw);
  const build = await verifyPublicBuildArtifacts({ raw, nonce, signal, repo, evidenceFetch: options.evidenceFetch });
  requireCondition(build.repo === repo && (build.platform === "tdx" || build.platform === "sev-snp"), "TEE_PUBLIC_BUILD_REJECTED");

  // The helper authenticated both section byte strings through the CPU report.
  const devices = JSON.parse(Buffer.from(envelope.device_evidence, "base64").toString("utf8"));
  const items: any[] = Array.isArray(devices.items) ? devices.items : [];
  const count = build.runtimeConfig.gpus;
  requireCondition(Number.isSafeInteger(count) && count >= 1 && items.length === count, "TEE_GPU_POLICY_REJECTED");
  items.forEach((item, index) => requireCondition(item.id === `gpu${index}` && item.kind === "gpu" && item.vendor === "nvidia" &&
    item.format === "https://tinfoil.sh/format/nvidia-gpu-evidence/v1" && item.evidence?.nonce === nonce, "TEE_GPU_POLICY_REJECTED"));
  const evidence = items.map(item => item.evidence);
  const checked = await runNvidiaVerifier({ evidence, nonce, signal, collateralOrigin: options.nvidiaCollateralOrigin });
  checkGpuAppraisal(checked, evidence, nonce, count);
  signal.throwIfAborted();
  const keys = JSON.parse(Buffer.from(envelope.crypto_material, "base64").toString("utf8")).items;
  const tls = keys.find((k: { id: string; format: string }) => k.id === "tls" && k.format === "https://tinfoil.sh/key/spki-fp-sha256/v1");
  const hpke = keys.find((k: { id: string; format: string }) => k.id === "hpke" && k.format === "https://tinfoil.sh/key/x25519-hpke/v1");
  requireCondition(/^[a-f0-9]{64}$/.test(tls?.data ?? "") && /^[a-f0-9]{64}$/.test(hpke?.data ?? ""), "TEE_ATTESTATION_REJECTED");
  const checkedAt = Date.now();
  const expiresAt = Math.min(checkedAt + 60000, challengeAt + 300000,
    Date.parse(build.codeFreshness) + 7 * 86400000, Date.parse(build.platformFreshness) + 7 * 86400000);
  requireCondition(Number.isSafeInteger(expiresAt) && expiresAt > checkedAt, "TEE_PUBLIC_SESSION_REJECTED");
  return { tls: tls.data, hpke: hpke.data, publicBuild: {
    checkedAt, expiresAt, workloadDigest: build.digest, platformDigest: build.platformDigest,
    cvmManifestDigest: build.cvmManifestDigest, imageDigest: build.containerBuild.imageDigest, configDigest: build.runtimeConfig.configDigest,
    platform: build.platform, gpus: count,
  } };
}

/**
 * Applies the GPU policy to NVIDIA's local verdict for every CPU-bound report:
 * one claim per device, all the same supported model, distinct devices, signed
 * references and revocation checks, version floors and the required mode.
 */
export function checkGpuAppraisal(checked: { code: number; stdout: string }, evidence: { arch?: unknown; evidence?: unknown }[], nonce: string, count: number) {
  let gpu: any;
  try { gpu = JSON.parse(checked.stdout); } catch { throw new TeeError("TEE_GPU_POLICY_REJECTED"); }
  requireCondition(checked.code === 0 && gpu.result_code === 0 && Array.isArray(gpu.claims) && gpu.claims.length === count && evidence.length === count, "TEE_GPU_POLICY_REJECTED");
  const hwmodel = gpu.claims[0]?.hwmodel;
  const arch = gpuPolicy(hwmodel)?.arch;
  const mode = requiredGpuMode(hwmodel, count);
  requireCondition(arch && mode, "TEE_GPU_POLICY_REJECTED");
  const devicesSeen = new Set<string>();
  gpu.claims.forEach((c: any, index: number) => {
    requireCondition(c.eat_nonce === nonce && c.hwmodel === hwmodel && evidence[index]!.arch === arch && c.measres === "success" &&
      c.dbgstat === "disabled" && c.secboot === true && typeof c.ueid === "string" && !devicesSeen.has(c.ueid) &&
      gpuVersionsAllowed(c.hwmodel, c["x-nvidia-gpu-driver-version"], c["x-nvidia-gpu-vbios-version"]), "TEE_GPU_POLICY_REJECTED");
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
