import { readBoundedBody, record, TeeError, type SecurityPolicy } from "pi-tee-core";
import { openEncryptedGatewayTransport } from "./direct.js";
import { appraiseWorker, PUBLIC_MODELS, WORKER_HOST, type PublicModel } from "./worker-appraisal.js";
import { selectPublicWorker } from "./public-session.js";
import { PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST, PUBLIC_BUILD_PROFILE_ID } from "./public-policy.js";

export const GATEWAY_MODELS = Object.freeze(["deepseek-v4-1-flash", "glm-5-3"] as const);
function gatewayModel(model: string): model is typeof GATEWAY_MODELS[number] {
  return GATEWAY_MODELS.some(allowed => model === allowed);
}

/** Untrusted hints only; the local public release authority never comes from this catalog. */
export async function discoverGatewayWorkers(model: string, signal: AbortSignal, fetch = globalThis.fetch): Promise<string[]> {
  if (!gatewayModel(model)) throw new TeeError("TEE_MODEL_UNAVAILABLE");
  const bound = AbortSignal.any([signal, AbortSignal.timeout(10000)]);
  try {
    const response = await fetch("https://inference-gateway.tinfoil.sh/catalog", { signal: bound, redirect: "error" });
    if (!response.ok) { await response.body?.cancel(); throw new TeeError("TEE_WORKER_DISCOVERY_UNAVAILABLE"); }
    const catalog = record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(response.body, 2 * 1024 * 1024, bound))));
    const entry = record(catalog[model]);
    if (entry.repo !== PUBLIC_MODELS[model] || !Array.isArray(entry.hosts) || !entry.hosts.length || entry.hosts.length > 128 ||
        entry.hosts.some(host => typeof host !== "string" || host.length > 253 || !WORKER_HOST.test(host))) throw new TeeError("TEE_WORKER_DISCOVERY_UNAVAILABLE");
    return [...new Set(entry.hosts as string[])];
  } catch { signal.throwIfAborted(); throw new TeeError("TEE_WORKER_DISCOVERY_UNAVAILABLE"); }
}

export async function openRatedGatewayTransport(signal: AbortSignal, model: string, policy: SecurityPolicy) {
  if (!gatewayModel(model)) throw new TeeError("TEE_MODEL_UNAVAILABLE");
  const { host, keys } = await selectPublicWorker(model, signal, {
    discover: (model, signal) => discoverGatewayWorkers(model, signal),
    reachable: async hosts => hosts,
    appraise: (model: PublicModel, host, signal) => appraiseWorker({ model, host, signal, policy, attestationRelay: "inference-gateway.tinfoil.sh" }),
  }, policy);
  const { platform: _platform, gpus: _gpus, ...admission } = keys.publicBuild;
  return {
    security: { ...keys.security, route: "tinfoil-gateway", observed: [...keys.security.observed,
      "TLS terminates at the unattested billing gateway, authenticated by WebPKI. It receives the API key, model and routing headers; bodies are sealed to the freshly appraised worker's own HPKE key.",
      "Gateway is a fallback when no direct worker qualifies: direct exposes the key and metadata to fewer parties.",
      "A 412 means the sealed worker is unavailable; this dispatch fails without a resend. A new request performs fresh selection and appraisal.",
    ] },
    admission: { profile: PUBLIC_BUILD_PROFILE_ID, model, authorityPolicyDigest: PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST, ...admission },
    transport: await openEncryptedGatewayTransport(signal, host, keys, model, keys.publicBuild.expiresAt),
  };
}
