import { randomBytes } from "node:crypto";
import { checkGpuAppraisal as checkGpuPolicy, rateGpuAppraisal, runNvidiaVerifier, runNrasVerifier, parsePolicy, TeeError, readBoundedBody, type SecurityPolicy, type RouteSecurity } from "pi-tee-core";
import { GPU_POLICIES } from "./gpu-policy.js";
import { verifyPublicBuildArtifacts } from "./public-build.js";
export { CERTIFICATE_CHAINS, REQUIRED_CLAIMS } from "pi-tee-core";

/** Models admitted under public builds and the one publisher repository for each. */
export const PUBLIC_MODELS = Object.freeze({
  "gemma4-31b": "tinfoilsh/confidential-gemma4-31b",
  "deepseek-v4-1-flash": "tinfoilsh/confidential-deepseek-v4-1-flash",
  "glm-5-3": "tinfoilsh/confidential-glm5-3-nvfp4",
});
export type PublicModel = keyof typeof PUBLIC_MODELS;
export const WORKER_HOST = /^[a-z0-9-]+-inf[0-9]+(?:-[0-9]+)?\.tinfoil\.containers\.tinfoil\.dev$/;

function requireCondition(ok: unknown, code: string): asserts ok { if (!ok) throw new TeeError(code); }

/**
 * Fresh public-build appraisal of one worker: CPU quote, release, guest,
 * container and runtime chain, then every CPU-bound GPU report. Returns the
 * quote-bound endpoint keys only after all of it passes.
 */
export async function appraiseWorker(options: {
  model: PublicModel; host: string; signal: AbortSignal; evidenceFetch?: typeof globalThis.fetch; nvidiaCollateralOrigin?: string;
  policy?: SecurityPolicy;
  /** External authenticated verifier seam; production uses the bundled helper. */
  verifyArtifacts?: typeof verifyPublicBuildArtifacts;
}): Promise<{ tls: string; hpke: string; security: RouteSecurity; publicBuild: {
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
  const policy = options.policy ?? parsePolicy();
  const build = await (options.verifyArtifacts ?? verifyPublicBuildArtifacts)({ raw, nonce, signal, repo, evidenceFetch: options.evidenceFetch, allowOutdated: policy.host !== "current" });
  requireCondition(build.repo === repo && (build.platform === "tdx" || build.platform === "sev-snp"), "TEE_PUBLIC_BUILD_REJECTED");
  requireCondition(build.hostLevel === 1 || (build.hostLevel === 2 && policy.host !== "current"), "TEE_CPU_POLICY_REJECTED");

  // The helper authenticated both section byte strings through the CPU report.
  const devices = JSON.parse(Buffer.from(envelope.device_evidence, "base64").toString("utf8"));
  const items: any[] = Array.isArray(devices.items) ? devices.items : [];
  const count = build.runtimeConfig.gpus;
  requireCondition(Number.isSafeInteger(count) && count >= 1, "TEE_GPU_POLICY_REJECTED");
  let rating: { gpu: 1 | 2 | 3; observed: string[] } = { gpu: 3, observed: ["GPU appraisal was not requested (gpu=unchecked)."] };
  if (policy.gpu !== "unchecked") {
    requireCondition(items.length === count, "TEE_GPU_POLICY_REJECTED");
    items.forEach((item, index) => requireCondition(item.id === `gpu${index}` && item.kind === "gpu" && item.vendor === "nvidia" &&
      item.format === "https://tinfoil.sh/format/nvidia-gpu-evidence/v1" && item.evidence?.nonce === nonce, "TEE_GPU_POLICY_REJECTED"));
    const evidence = items.map(item => item.evidence);
    const checked = policy.verifier === "nras" ? await runNrasVerifier({ evidence, nonce, signal }) :
      await runNvidiaVerifier({ evidence, nonce, signal, collateralOrigin: options.nvidiaCollateralOrigin });
    rating = rateGpuAppraisal(GPU_POLICIES, checked, evidence, nonce, count, { cpuFresh: true, completeCoverage: true, cpuHash: true });
  }
  signal.throwIfAborted();
  const keys = JSON.parse(Buffer.from(envelope.crypto_material, "base64").toString("utf8")).items;
  const tls = keys.find((k: { id: string; format: string }) => k.id === "tls" && k.format === "https://tinfoil.sh/key/spki-fp-sha256/v1");
  const hpke = keys.find((k: { id: string; format: string }) => k.id === "hpke" && k.format === "https://tinfoil.sh/key/x25519-hpke/v1");
  requireCondition(/^[a-f0-9]{64}$/.test(tls?.data ?? "") && /^[a-f0-9]{64}$/.test(hpke?.data ?? ""), "TEE_ATTESTATION_REJECTED");
  const checkedAt = Date.now();
  const expiresAt = Math.min(checkedAt + 60000, challengeAt + 300000,
    Date.parse(build.codeFreshness) + 7 * 86400000, Date.parse(build.platformFreshness) + 7 * 86400000);
  requireCondition(Number.isSafeInteger(expiresAt) && expiresAt > checkedAt, "TEE_PUBLIC_SESSION_REJECTED");
  return { tls: tls.data, hpke: hpke.data, security: {
    route: "tinfoil-direct", provider: "Tinfoil", cpuVerified: true, code: 1, host: build.hostLevel, gpu: rating.gpu, egress: 2, build: 3, review: 3,
    observed: [options.host, `${build.platform}; ${count} GPUs declared by the authenticated release.`, ...rating.observed,
      ...(build.hostLevel === 2 ? ["AMD firmware is below local floors; authenticated publisher minima and production restrictions still passed."] : []),
      "Intel OutOfDate TDX workers are unavailable under every policy: the pinned verifier rejects them during authentication.",
      "Tinfoil handling commitments have not been reviewed."],
  }, publicBuild: {
    checkedAt, expiresAt, workloadDigest: build.digest, platformDigest: build.platformDigest,
    cvmManifestDigest: build.cvmManifestDigest, imageDigest: build.containerBuild.imageDigest, configDigest: build.runtimeConfig.configDigest,
    platform: build.platform, gpus: count,
  } };
}

/** Applies Tinfoil's GPU policy to NVIDIA's local verdict for every CPU-bound report. */
export function checkGpuAppraisal(checked: { code: number; stdout: string }, evidence: { arch?: unknown; evidence?: unknown }[], nonce: string, count: number) {
  checkGpuPolicy(GPU_POLICIES, checked, evidence, nonce, count);
}
