import { TeeError, type SdkTransport, type PublicBuildProfile } from "pi-tee-core";
import { openEncryptedWorkerTransport } from "./direct.js";
import { INTEL_CANDIDATE, qualifyIntelCandidate } from "./intel-appraisal.js";
import { PUBLIC_BUILD_PROFILE_ID, PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST } from "./public-policy.js";

export async function openIntelTinfoilTransport(signal: AbortSignal, mode: "frozen" | "public-builds" = "frozen"): Promise<SdkTransport> {
  const cpuVerifier = mode === "public-builds" ? process.env.PI_TINFOIL_PUBLIC_BUILD_VERIFIER : process.env.PI_TINFOIL_CPU_VERIFIER;
  const nvatDir = process.env.PI_TINFOIL_NVAT_DIR;
  if (!cpuVerifier || !nvatDir || process.platform !== "darwin" || process.arch !== "arm64") throw new TeeError("TEE_RUNTIME_UNSUPPORTED");
  const keys = await qualifyIntelCandidate({ cpuVerifier, nvatDir, signal, mode });
  return openEncryptedWorkerTransport(signal, INTEL_CANDIDATE.host, keys, "cache_salt");
}

export const INTEL_PUBLIC_BUILD_PROFILE: PublicBuildProfile = Object.freeze({
  id: PUBLIC_BUILD_PROFILE_ID,
  authorityPolicyDigest: PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST,
  modelIds: Object.freeze([INTEL_CANDIDATE.model]),
  baseUrl: `https://${INTEL_CANDIDATE.host}/v1`,
  async openSession({ signal, model }: Parameters<PublicBuildProfile["openSession"]>[0]) {
    if (model.id !== INTEL_CANDIDATE.model) throw new TeeError("TEE_MODEL_UNAVAILABLE");
    const cpuVerifier = process.env.PI_TINFOIL_PUBLIC_BUILD_VERIFIER;
    const nvatDir = process.env.PI_TINFOIL_NVAT_DIR;
    if (!cpuVerifier || !nvatDir || process.platform !== "darwin" || process.arch !== "arm64") throw new TeeError("TEE_RUNTIME_UNSUPPORTED");
    const keys = await qualifyIntelCandidate({ cpuVerifier, nvatDir, signal, mode: "public-builds" });
    if (!keys.publicBuild) throw new TeeError("TEE_PUBLIC_SESSION_REJECTED");
    signal.throwIfAborted();
    return {
      admission: { profile: PUBLIC_BUILD_PROFILE_ID, model: model.id, authorityPolicyDigest: PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST, ...keys.publicBuild },
      transport: await openEncryptedWorkerTransport(signal, INTEL_CANDIDATE.host, keys, "cache_salt"),
    };
  },
});
