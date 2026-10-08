import { randomInt } from "node:crypto";
import { TeeError, type PublicBuildProfile, type SdkTransport } from "pi-tee-core";
import { openEncryptedWorkerTransport } from "./direct.js";
import { PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST, PUBLIC_BUILD_PROFILE_ID } from "./public-policy.js";
import { appraiseWorker, PUBLIC_MODELS, type PublicModel } from "./worker-appraisal.js";
import { discoverTinfoilWorkers } from "./worker-discovery.js";

// Requests address this canonical endpoint; the transport dials only the
// worker whose evidence was just appraised. `.invalid` never resolves.
export const PUBLIC_BUILD_BASE_URL = "https://direct-worker.tinfoil.invalid/v1";
const MAX_WORKER_ATTEMPTS = 4;
// Untrusted ordering hint only: the last host that passed is tried first.
const lastHealthy = new Map<string, string>();

function isPublicModel(model: string): model is PublicModel { return Object.hasOwn(PUBLIC_MODELS, model); }

async function appraiseDiscoveredWorker(model: PublicModel, signal: AbortSignal) {
  const candidates = (await discoverTinfoilWorkers({ model, repository: PUBLIC_MODELS[model], signal })).map(candidate => candidate.host);
  for (let index = candidates.length - 1; index > 0; index--) {
    const other = randomInt(index + 1);
    [candidates[index], candidates[other]] = [candidates[other]!, candidates[index]!];
  }
  const preferred = lastHealthy.get(model);
  if (preferred && candidates.includes(preferred)) candidates.unshift(...candidates.splice(candidates.indexOf(preferred), 1));
  // Each candidate gets a fresh challenge and full appraisal; discovery data
  // never authorizes one, and a failure on one host relaxes nothing for the next.
  let rejection: TeeError | undefined;
  for (const host of candidates.slice(0, MAX_WORKER_ATTEMPTS)) {
    signal.throwIfAborted();
    try {
      const keys = await appraiseWorker({ model, host, signal: AbortSignal.any([signal, AbortSignal.timeout(120000)]) });
      lastHealthy.set(model, host);
      return { host, keys };
    } catch (error) {
      signal.throwIfAborted();
      if (lastHealthy.get(model) === host) lastHealthy.delete(model);
      // Report a verification failure in preference to unreachable workers.
      if (error instanceof TeeError && error.code !== "TEE_ATTESTATION_REJECTED") rejection ??= error;
    }
  }
  throw rejection ?? new TeeError("TEE_PUBLIC_BUILD_DEPLOYMENT_UNAVAILABLE");
}

/** Experimental SDK-policy route over the same appraisal. */
export async function openPublicWorkerTransport(signal: AbortSignal, model: string): Promise<SdkTransport> {
  if (!isPublicModel(model)) throw new TeeError("TEE_MODEL_UNAVAILABLE");
  const { host, keys } = await appraiseDiscoveredWorker(model, signal);
  return openEncryptedWorkerTransport(signal, host, keys, "cache_salt", keys.publicBuild.expiresAt, PUBLIC_BUILD_BASE_URL);
}

export const PUBLIC_BUILD_PROFILE: PublicBuildProfile = Object.freeze({
  id: PUBLIC_BUILD_PROFILE_ID,
  assumptions: Object.freeze([
    "Local OS, clock, Pi/runtime, enabled extensions/hooks/tools, locked dependencies and the hash-checked WebAssembly CPU-helper/NVIDIA verifier modules are trusted.",
    "Intel TDX and AMD SEV-SNP manufacturer roots, hardware/firmware, signed collateral and revocation authenticate fresh CPU-bound device bytes and endpoint keys. TDX requires UpToDate appraisal and local floors; SEV-SNP requires publisher TCB floors, AMD's CRL, a non-debug, non-migratable VMPL0 guest and the pinned tinfoilsh/edk2 OVMF in the recomputed launch digest.",
    "NVIDIA device/reference roots, fresh OCSP, signed golden references and the authenticated protected mode (SPT for one GPU, Blackwell MPT for several) are trusted with the manufacturer's protected-transfer/reset contract; local version floors constrain upgrades.",
    "The public Tinfoil workload repositories for Gemma 4 31B, DeepSeek V4.1 Flash and GLM-5.3, plus the guest, platform and freshness workflows, GitHub OIDC/hosted builds and the finite Sigstore roots, authorize updates automatically.",
    "Those accepted publishers are trusted for correct measurements, safe dependency selection, private per-boot keys, immutable runtime/model inputs, closed engine egress and preserved GPU-channel/reset behavior.",
    "OCI build/source claims inherit the workload publisher's release endorsement. Independent rebuilds and per-release source review are outside this policy.",
    "Tinfoil receives API credentials and host/path/domain metadata for authorization/billing, controls availability and chooses which advertised worker is reachable. The serving contract declares all plaintext/key-capable guest processes and constrained operator inputs.",
    "The owned TLS/EHBP transport binds keys before credentials/body, sends once and uses a fresh encrypted cache salt. This contract covers its dispatches; whole-Pi-session protection remains unestablished.",
  ]),
  authorityPolicyDigest: PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST,
  modelIds: Object.freeze(Object.keys(PUBLIC_MODELS)),
  baseUrl: PUBLIC_BUILD_BASE_URL,
  async openSession({ signal, model }: Parameters<PublicBuildProfile["openSession"]>[0]) {
    if (!isPublicModel(model.id)) throw new TeeError("TEE_MODEL_UNAVAILABLE");
    const { host, keys } = await appraiseDiscoveredWorker(model.id, signal);
    signal.throwIfAborted();
    const { platform: _platform, gpus: _gpus, ...admission } = keys.publicBuild;
    return {
      admission: { profile: PUBLIC_BUILD_PROFILE_ID, model: model.id, authorityPolicyDigest: PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST, ...admission },
      transport: await openEncryptedWorkerTransport(signal, host, keys, "cache_salt", keys.publicBuild.expiresAt, PUBLIC_BUILD_BASE_URL),
    };
  },
});
