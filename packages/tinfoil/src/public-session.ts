import { randomInt } from "node:crypto";
import { connect as netConnect } from "node:net";
import { assessRoute, compareRoutes, parsePolicy, RouteRejection, TeeError, type SecurityPolicy, type PublicBuildProfile, type SdkTransport } from "pi-tee-core";
import { openEncryptedWorkerTransport } from "./direct.js";
import { PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST, PUBLIC_BUILD_PROFILE_ID } from "./public-policy.js";
import { appraiseWorker, PUBLIC_MODELS, type PublicModel } from "./worker-appraisal.js";
import { discoverTinfoilWorkers } from "./worker-discovery.js";

// Requests address this canonical endpoint; the transport dials only the
// worker whose evidence was just appraised. `.invalid` never resolves.
export const PUBLIC_BUILD_BASE_URL = "https://direct-worker.tinfoil.invalid/v1";
const MAX_WORKER_ATTEMPTS = 8;
// Untrusted ordering hint only: the last host that passed is tried first.
const lastHealthy = new Map<string, string>();

function isPublicModel(model: string): model is PublicModel { return Object.hasOwn(PUBLIC_MODELS, model); }

type WorkerKeys = Awaited<ReturnType<typeof appraiseWorker>>;
type SelectionDeps = {
  discover: (model: PublicModel, signal: AbortSignal) => Promise<string[]>;
  reachable: (hosts: string[], signal: AbortSignal) => Promise<string[]>;
  appraise: (model: PublicModel, host: string, signal: AbortSignal) => Promise<WorkerKeys>;
};

// TCP reachability only: many advertised workers accept no direct
// connections. It authorizes nothing; it keeps them from using up appraisals.
// At most 16 attempts run at once, and probing stops after eight reachable
// hosts, matching the appraisal budget.
// Delivery order decides which hosts finish probing first; reachability is only
// an availability hint. The caller takes a bounded slice and appraises it afresh.
function reachableHosts(hosts: string[], signal: AbortSignal): Promise<string[]> {
  return new Promise(resolve => {
    const reachable: string[] = [];
    let next = 0, running = 0, finished = false;
    const done = () => { if (!finished) { finished = true; resolve(reachable); } };
    const launch = () => {
      while (!finished && running < 16 && next < hosts.length && reachable.length < 8 && !signal.aborted) {
        const host = hosts[next++]!;
        running++;
        probe(host, signal).then(ok => {
          running--;
          if (ok) reachable.push(host);
          if (reachable.length >= 8 || signal.aborted || (next >= hosts.length && running === 0)) done();
          else launch();
        });
      }
      if (running === 0) done();
    };
    launch();
  });
}

function probe(host: string, signal: AbortSignal): Promise<boolean> {
  return new Promise(done => {
    const socket = netConnect({ host, port: 443 });
    const finish = (ok: boolean) => { clearTimeout(timer); signal.removeEventListener("abort", abort); socket.destroy(); done(ok); };
    const abort = () => finish(false);
    const timer = setTimeout(() => finish(false), 3000);
    signal.addEventListener("abort", abort, { once: true });
    socket.once("connect", () => finish(true)).once("error", () => finish(false));
  });
}

const defaultDeps: SelectionDeps = {
  discover: async (model, signal) => (await discoverTinfoilWorkers({ model, repository: PUBLIC_MODELS[model], signal })).map(candidate => candidate.host),
  reachable: reachableHosts,
  appraise: (model, host, signal) => appraiseWorker({ model, host, signal: AbortSignal.any([signal, AbortSignal.timeout(120000)]) }),
};

export async function selectPublicWorker(model: PublicModel, signal: AbortSignal, deps: Partial<SelectionDeps> = {}, policy: SecurityPolicy = parsePolicy()) {
  const { discover, reachable } = { ...defaultDeps, ...deps };
  const appraise = deps.appraise ?? ((model: PublicModel, host: string, signal: AbortSignal) => appraiseWorker({ model, host, signal: AbortSignal.any([signal, AbortSignal.timeout(120000)]), policy }));
  const candidates = await reachable(await discover(model, signal), signal);
  signal.throwIfAborted();
  for (let index = candidates.length - 1; index > 0; index--) {
    const other = randomInt(index + 1);
    [candidates[index], candidates[other]] = [candidates[other]!, candidates[index]!];
  }
  const preferred = lastHealthy.get(model);
  if (preferred && candidates.includes(preferred)) candidates.unshift(...candidates.splice(candidates.indexOf(preferred), 1));
  // Each candidate gets a fresh challenge and full appraisal; discovery and
  // reachability never authorize one, and a failure relaxes nothing for the next.
  let rejection: TeeError | undefined;
  let unavailable: TeeError | undefined;
  let best: { host: string; keys: WorkerKeys } | undefined;
  let bestRejected: WorkerKeys["security"] | undefined;
  for (const host of candidates.slice(0, MAX_WORKER_ATTEMPTS)) {
    signal.throwIfAborted();
    try {
      const keys = await appraise(model, host, signal);
      if (!assessRoute(policy, keys.security).accepted) {
        if (!bestRejected || compareRoutes(keys.security, bestRejected) < 0) bestRejected = keys.security;
        throw new RouteRejection(keys.security);
      }
      if (!best || compareRoutes(keys.security, best.keys.security) < 0) best = { host, keys };
      // G3 is the best possible reported GPU level when appraisal is unchecked.
      if (keys.security.host === 1 && (keys.security.gpu === 1 || policy.gpu === "unchecked")) break;
    } catch (error) {
      signal.throwIfAborted();
      if (lastHealthy.get(model) === host) lastHealthy.delete(model);
      // Report a verification failure in preference to unreachable workers.
      if (error instanceof TeeError && error.code !== "TEE_ATTESTATION_REJECTED" && error.code !== "TEE_PUBLIC_ARTIFACT_UNAVAILABLE") rejection ??= error;
      else if (error instanceof TeeError && error.code === "TEE_PUBLIC_ARTIFACT_UNAVAILABLE") unavailable = error;
    }
  }
  if (best) { lastHealthy.set(model, best.host); return best; }
  throw (bestRejected && new RouteRejection(bestRejected)) ?? rejection ?? unavailable ?? new TeeError("TEE_PUBLIC_BUILD_DEPLOYMENT_UNAVAILABLE");
}

export async function openRatedPublicWorkerTransport(signal: AbortSignal, model: string, policy: SecurityPolicy) {
  if (!isPublicModel(model)) throw new TeeError("TEE_MODEL_UNAVAILABLE");
  const { host, keys } = await selectPublicWorker(model, signal, {}, policy);
  const { platform: _platform, gpus: _gpus, ...admission } = keys.publicBuild;
  return {
    security: keys.security,
    admission: { profile: PUBLIC_BUILD_PROFILE_ID, model, authorityPolicyDigest: PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST, ...admission },
    transport: await openEncryptedWorkerTransport(signal, host, keys, "cache_salt", keys.publicBuild.expiresAt, PUBLIC_BUILD_BASE_URL),
  };
}

/** SDK-policy route over the same appraisal. */
export async function openPublicWorkerTransport(signal: AbortSignal, model: string): Promise<SdkTransport> {
  if (!isPublicModel(model)) throw new TeeError("TEE_MODEL_UNAVAILABLE");
  const { host, keys } = await selectPublicWorker(model, signal);
  return openEncryptedWorkerTransport(signal, host, keys, "cache_salt", keys.publicBuild.expiresAt, PUBLIC_BUILD_BASE_URL);
}

export const PUBLIC_BUILD_PROFILE: PublicBuildProfile = Object.freeze({
  id: PUBLIC_BUILD_PROFILE_ID,
  assumptions: Object.freeze([
    "Local OS, clock, Pi/runtime, enabled extensions/hooks/tools, locked dependencies and the hash-checked WebAssembly CPU-helper/NVIDIA verifier modules are trusted.",
    "Intel TDX and AMD SEV-SNP manufacturer roots, hardware/firmware, signed collateral and revocation authenticate fresh CPU-bound device bytes and endpoint keys. Only production machine policies are accepted. TDX requires UpToDate appraisal and local floors; SEV-SNP requires firmware with the fixes from AMD-SB-3019, 3020 and 3027 for the reported CPU, AMD's CRL, a non-debug, non-migratable VMPL0 guest and the pinned tinfoilsh/edk2 OVMF in the recomputed launch digest.",
    "NVIDIA device/reference roots, fresh OCSP, signed golden references and the authenticated protected mode (SPT for one GPU, Blackwell MPT for several) are trusted with the manufacturer's protected-transfer/reset contract; local version floors constrain upgrades.",
    "The public Tinfoil workload repositories for Gemma 4 31B, DeepSeek V4.1 Flash and GLM-5.3, plus the guest, platform and freshness workflows, GitHub OIDC/hosted builds and the finite Sigstore roots, authorize updates automatically.",
    "Those accepted publishers are trusted for correct measurements, safe dependency selection, private per-boot keys, immutable runtime/model inputs, closed engine egress and preserved GPU-channel/reset behavior. The engine image runs vLLM, optionally behind Tinfoil's inference-sidecar proxy, which also sees plaintext.",
    "OCI build/source claims inherit the workload publisher's release endorsement. Independent rebuilds and per-release source review are outside this policy.",
    "Tinfoil receives API credentials and host/path/domain metadata for authorization/billing, controls availability and chooses which advertised worker is reachable. The serving contract declares all plaintext/key-capable guest processes and constrained operator inputs.",
    "The owned TLS/EHBP transport binds keys before credentials/body, sends once and uses a fresh encrypted cache salt. This contract covers its dispatches; whole-Pi-session protection remains unestablished.",
  ]),
  authorityPolicyDigest: PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST,
  modelIds: Object.freeze(Object.keys(PUBLIC_MODELS)),
  baseUrl: PUBLIC_BUILD_BASE_URL,
  async openSession({ signal, model }: Parameters<PublicBuildProfile["openSession"]>[0]) {
    if (!isPublicModel(model.id)) throw new TeeError("TEE_MODEL_UNAVAILABLE");
    const { host, keys } = await selectPublicWorker(model.id, signal);
    signal.throwIfAborted();
    const { platform: _platform, gpus: _gpus, ...admission } = keys.publicBuild;
    return {
      admission: { profile: PUBLIC_BUILD_PROFILE_ID, model: model.id, authorityPolicyDigest: PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST, ...admission },
      transport: await openEncryptedWorkerTransport(signal, host, keys, "cache_salt", keys.publicBuild.expiresAt, PUBLIC_BUILD_BASE_URL),
    };
  },
});
