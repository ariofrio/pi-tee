import { randomBytes } from "node:crypto";
import { TeeError, readBoundedBody } from "pi-tee-core";
import { parseHopperGpuMode } from "./gpu-mode.js";
import { gpuVersionsAllowed } from "./gpu-policy.js";
import { verifyPublicBuildArtifacts } from "./public-build.js";
import { runNvidiaVerifier } from "./wasm-verifiers.js";

export const INTEL_CANDIDATE = Object.freeze({
  host: "gemma4-31b-inf8-0.tinfoil.containers.tinfoil.dev",
  model: "gemma4-31b",
});
function requireCondition(ok: unknown, code: string): asserts ok { if (!ok) throw new TeeError(code); }

export async function qualifyIntelCandidate(options: {
  signal: AbortSignal; evidenceFetch?: typeof globalThis.fetch; nvidiaCollateralOrigin?: string;
}): Promise<{ tls: string; hpke: string; publicBuild: {
  checkedAt: number; expiresAt: number; workloadDigest: string; platformDigest: string;
  cvmManifestDigest: string; imageDigest: string; configDigest: string;
} }> {
  const challengeAt = Date.now();
  const signal = AbortSignal.any([options.signal, AbortSignal.timeout(240000)]);
  signal.throwIfAborted();
  const nonce = randomBytes(32).toString("hex");
  const response = await (options.evidenceFetch ?? globalThis.fetch)(`https://${INTEL_CANDIDATE.host}/.well-known/tinfoil-attestation?nonce=${nonce}`, { signal, redirect: "error" });
  requireCondition(response.ok, "TEE_ATTESTATION_REJECTED");
  const raw = await readBoundedBody(response.body, 2 * 1024 * 1024, signal);
  const envelope = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  const build = await verifyPublicBuildArtifacts({ raw: new TextDecoder("utf-8", { fatal: true }).decode(raw), nonce, signal, evidenceFetch: options.evidenceFetch });
  // The strict Go parser authenticated both section byte strings before JS uses them.
  const devices = JSON.parse(Buffer.from(envelope.device_evidence, "base64").toString("utf8"));
  requireCondition(devices.items?.length === 1 && devices.items[0].id === "gpu0" && devices.items[0].kind === "gpu" && devices.items[0].vendor === "nvidia" && devices.items[0].format === "https://tinfoil.sh/format/nvidia-gpu-evidence/v1", "TEE_GPU_POLICY_REJECTED");
  const evidence = devices.items[0].evidence;
  requireCondition(evidence.nonce === nonce && evidence.arch === "HOPPER", "TEE_GPU_POLICY_REJECTED");
  const checked = await runNvidiaVerifier({ evidence: [evidence], nonce, signal, collateralOrigin: options.nvidiaCollateralOrigin });
  let gpu: any;
  try { gpu = JSON.parse(checked.stdout); } catch { throw new TeeError("TEE_GPU_POLICY_REJECTED"); }
  requireCondition(checked.code === 0 && gpu.result_code === 0 && Array.isArray(gpu.claims) && gpu.claims.length === 1, "TEE_GPU_POLICY_REJECTED");
  const c = gpu.claims[0];
  requireCondition(c.eat_nonce === nonce && c.hwmodel === "GH100 A01 GSP BROM" && c.measres === "success" && c.dbgstat === "disabled" && c.secboot === true &&
    gpuVersionsAllowed(c["x-nvidia-gpu-driver-version"], c["x-nvidia-gpu-vbios-version"], "public-builds") &&
    c["x-nvidia-gpu-attestation-report-signature-verified"] === true && c["x-nvidia-gpu-attestation-report-nonce-match"] === true, "TEE_GPU_POLICY_REJECTED");
  for (const field of ["x-nvidia-gpu-arch-check", "x-nvidia-gpu-attestation-report-parsed", "x-nvidia-gpu-attestation-report-cert-chain-fwid-match", "x-nvidia-gpu-driver-rim-fetched", "x-nvidia-gpu-driver-rim-measurements-available", "x-nvidia-gpu-driver-rim-signature-verified", "x-nvidia-gpu-driver-rim-version-match", "x-nvidia-gpu-vbios-rim-fetched", "x-nvidia-gpu-vbios-rim-measurements-available", "x-nvidia-gpu-vbios-rim-signature-verified", "x-nvidia-gpu-vbios-rim-version-match", "x-nvidia-gpu-vbios-index-no-conflict"]) {
    requireCondition(c[field] === true, "TEE_GPU_POLICY_REJECTED");
  }
  for (const field of ["x-nvidia-gpu-attestation-report-cert-chain", "x-nvidia-gpu-driver-rim-cert-chain", "x-nvidia-gpu-vbios-rim-cert-chain"]) {
    const chain = c[field];
    requireCondition(chain?.["x-nvidia-cert-status"] === "valid" && chain["x-nvidia-cert-ocsp-status"] === "good" && chain["x-nvidia-cert-ocsp-response-valid"] === true && chain["x-nvidia-cert-ocsp-nonce-matches"] === true, "TEE_GPU_POLICY_REJECTED");
  }
  requireCondition(parseHopperGpuMode(evidence.evidence) === "spt", "TEE_GPU_MODE_REJECTED");
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
  } };
}
