import { TeeError, type SdkTransport, type PublicBuildProfile } from "pi-tee-core";
import { openEncryptedWorkerTransport } from "./direct.js";
import { INTEL_CANDIDATE, qualifyIntelCandidate } from "./intel-appraisal.js";
import { PUBLIC_BUILD_PROFILE_ID, PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST } from "./public-policy.js";

export async function openIntelTinfoilTransport(signal: AbortSignal, mode: "frozen" | "public-builds" = "frozen"): Promise<SdkTransport> {
  const cpuVerifier = mode === "public-builds" ? process.env.PI_TINFOIL_PUBLIC_BUILD_VERIFIER : process.env.PI_TINFOIL_CPU_VERIFIER;
  const nvatDir = process.env.PI_TINFOIL_NVAT_DIR;
  if (!cpuVerifier || !nvatDir || process.platform !== "darwin" || process.arch !== "arm64") throw new TeeError("TEE_RUNTIME_UNSUPPORTED");
  const keys = await qualifyIntelCandidate({ cpuVerifier, nvatDir, signal, mode });
  return openEncryptedWorkerTransport(signal, INTEL_CANDIDATE.host, keys, "cache_salt", undefined, keys.publicBuild?.expiresAt);
}

export const INTEL_PUBLIC_BUILD_PROFILE: PublicBuildProfile = Object.freeze({
  id: PUBLIC_BUILD_PROFILE_ID,
  assumptions: Object.freeze([
    "Local OS, clock, Pi/runtime, enabled extensions/hooks/tools, locked dependencies, pinned helper/NVIDIA artifacts and the checked local Docker daemon are trusted.",
    "Intel TDX manufacturer roots, hardware/firmware, signed collateral/revocation and UpToDate security appraisal authenticate fresh CPU-bound device bytes and endpoint keys.",
    "NVIDIA device/reference roots, fresh OCSP, signed golden references, SPT mode and manufacturer protected-transfer/reset contracts are trusted; local version floors constrain upgrades.",
    "The public Tinfoil workload, guest, platform and freshness workflow authorities plus GitHub OIDC/hosted builds and the finite Sigstore roots authorize updates automatically.",
    "Those accepted publishers are trusted for correct measurements, safe dependency selection, private per-boot keys, immutable runtime/model inputs, closed engine egress and preserved GPU-channel/reset behavior.",
    "OCI build/source claims inherit the workload publisher's release endorsement. Independent rebuilds and per-release source review are outside this policy.",
    "Tinfoil receives API credentials and host/path/domain metadata for authorization/billing and controls availability. The serving contract declares all plaintext/key-capable guest processes and constrained operator inputs.",
    "The owned TLS/EHBP transport binds keys before credentials/body, sends once and uses a fresh encrypted cache salt. This contract covers its dispatches; whole-Pi-session protection remains unestablished.",
  ]),
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
      transport: await openEncryptedWorkerTransport(signal, INTEL_CANDIDATE.host, keys, "cache_salt", undefined, keys.publicBuild?.expiresAt),
    };
  },
});
