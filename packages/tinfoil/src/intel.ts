import { TeeError, type SdkTransport } from "pi-tee-core";
import { openEncryptedWorkerTransport } from "./direct.js";
import { INTEL_CANDIDATE, qualifyIntelCandidate } from "./intel-appraisal.js";

export async function openIntelTinfoilTransport(signal: AbortSignal): Promise<SdkTransport> {
  const cpuVerifier = process.env.PI_TINFOIL_CPU_VERIFIER;
  const nvatDir = process.env.PI_TINFOIL_NVAT_DIR;
  if (!cpuVerifier || !nvatDir || process.platform !== "darwin" || process.arch !== "arm64") throw new TeeError("TEE_RUNTIME_UNSUPPORTED");
  const keys = await qualifyIntelCandidate({ cpuVerifier, nvatDir, signal });
  return openEncryptedWorkerTransport(signal, INTEL_CANDIDATE.host, keys, "cache_salt");
}
