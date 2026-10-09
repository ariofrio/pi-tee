import { createHash } from "node:crypto";
import { fetchUpstream, readBoundedBody, record, RouteRejection, TeeError, type SecurityPolicy } from "pi-tee-core";
import { GATEWAY_MODELS, openEncryptedGatewayTransport, TINFOIL_GATEWAY_BASE_URL } from "./direct.js";
import { appraiseWorker, PUBLIC_MODELS, WORKER_HOST, type PublicModel } from "./worker-appraisal.js";
import { selectPublicWorker } from "./public-session.js";
import { PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST, PUBLIC_BUILD_PROFILE_ID } from "./public-policy.js";

export const GATEWAY_LIMITATIONS = [
  "Gateway EHBP authenticates individual frames, but has no authenticated end-of-stream marker: the gateway can truncate at a frame boundary. Pi's SSE finish_reason check detects an unfinished completion; trailing usage can still disappear.",
  "Gateway EHBP has no anti-replay: the gateway can replay a sealed request to the same worker, causing duplicate inference and billing, and return an equally authentic duplicate response. Client send-once does not prevent gateway replay.",
];

export { GATEWAY_MODELS } from "./direct.js";
// Seal headers route ciphertext; the appraised worker key authenticates it.
// Include the extra metadata recipient and frame/replay limits in admission identity.
const gatewayAuthorityDigest = createHash("sha256").update(JSON.stringify({
  workerAppraisal: PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST, models: GATEWAY_MODELS,
  transport: { endpoint: TINFOIL_GATEWAY_BASE_URL, tls: "TLS1.3-WebPKI", body: "worker-key-EHBP", sends: 1, rotation: "reject", seal: "X-Tinfoil-Seal: appraised worker", cache: "fresh-encrypted-cache_salt", responseCompleteness: "frames-only-SSE-finish_reason", replayProtection: "none" },
  metadataRecipient: "unattested inference-gateway.tinfoil.sh receives API key, model and headers",
})).digest("hex");
function gatewayModel(model: string): model is typeof GATEWAY_MODELS[number] {
  return GATEWAY_MODELS.some(allowed => model === allowed);
}

/** Untrusted hints only; the local public release authority never comes from this catalog. */
export async function discoverGatewayWorkers(model: string, signal: AbortSignal, fetch = globalThis.fetch): Promise<string[]> {
  if (!gatewayModel(model)) throw new TeeError("TEE_MODEL_UNAVAILABLE");
  const bound = AbortSignal.any([signal, AbortSignal.timeout(10000)]);
  try {
    const response = await fetchUpstream(fetch, "https://inference-gateway.tinfoil.sh/catalog", { signal: bound, redirect: "error" }, "evidence", "TEE_WORKER_DISCOVERY_UNAVAILABLE");
    const catalog = record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(response.body, 2 * 1024 * 1024, bound))));
    const entry = record(catalog[model]);
    if (entry.repo !== PUBLIC_MODELS[model] || !Array.isArray(entry.hosts) || !entry.hosts.length || entry.hosts.length > 128 ||
        entry.hosts.some(host => typeof host !== "string" || host.length > 253 || !WORKER_HOST.test(host))) throw new TeeError("TEE_WORKER_DISCOVERY_UNAVAILABLE");
    return [...new Set(entry.hosts as string[])];
  } catch (error) { signal.throwIfAborted(); throw new TeeError("TEE_WORKER_DISCOVERY_UNAVAILABLE", undefined, error instanceof TeeError ? error.upstream : undefined); }
}

export async function openRatedGatewayTransport(signal: AbortSignal, model: string, policy: SecurityPolicy,
  appraise = (model: PublicModel, host: string, signal: AbortSignal) => appraiseWorker({ model, host,
    signal: AbortSignal.any([signal, AbortSignal.timeout(120000)]), policy, attestationRelay: "inference-gateway.tinfoil.sh" }),
) {
  if (!gatewayModel(model)) throw new TeeError("TEE_MODEL_UNAVAILABLE");
  const { host, keys } = await selectPublicWorker(model, signal, {
    discover: (model, signal) => discoverGatewayWorkers(model, signal),
    reachable: async hosts => hosts,
    appraise,
  }, policy).catch(error => {
    if (error instanceof RouteRejection) throw new RouteRejection({ ...error.security, route: "tinfoil-gateway" });
    throw error;
  });
  const { platform: _platform, gpus: _gpus, ...admission } = keys.publicBuild;
  return {
    security: { ...keys.security, route: "tinfoil-gateway", observed: [...keys.security.observed,
      "TLS terminates at the unattested billing gateway, authenticated by WebPKI. It receives the API key, model and routing headers; bodies are sealed to the freshly appraised worker's own HPKE key.",
      "Gateway is a fallback when no direct worker qualifies: direct exposes the key and metadata to fewer parties.",
      "A 412 means the sealed worker is unavailable; this dispatch fails without a resend. A new request performs fresh selection and appraisal.",
      ...GATEWAY_LIMITATIONS,
    ] },
    admission: { profile: `${PUBLIC_BUILD_PROFILE_ID}-gateway`, model, authorityPolicyDigest: gatewayAuthorityDigest, ...admission },
    transport: await openEncryptedGatewayTransport(signal, host, keys, model, keys.publicBuild.expiresAt),
  };
}
