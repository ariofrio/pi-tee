import { randomBytes } from "node:crypto";
import { assessRoute, entries, fetchUpstream, MAX_REQUEST_BYTES, readBoundedBody, record, RouteRejection, TeeError, webPkiTlsFetch, withAbort,
  type RouteSecurity, type SecurityPolicy, type SdkTransport } from "pi-tee-core";
import { CHUTES_API_URL, CHUTES_BASE_URL, parseChutesCatalog, UUID } from "./catalog.js";
import { createE2eeRequest, decryptE2eeStream } from "./crypto.js";
import { base64, verifyChutesInstance, type CpuSeams } from "./evidence.js";

export interface ChutesSeams { fetch?: typeof globalThis.fetch; invoke?: typeof globalThis.fetch; cpu?: CpuSeams }

export function chutesInvocationFetch(endpoint: string, expiresAt: number): typeof globalThis.fetch { return webPkiTlsFetch(endpoint, expiresAt); }

export async function openChutesTransport(apiKey: string, model: string, signal: AbortSignal, policy: SecurityPolicy, seams: ChutesSeams = {}): Promise<SdkTransport & { security: RouteSecurity }> {
  const controller = new AbortController();
  const bound = AbortSignal.any([signal, controller.signal, AbortSignal.timeout(60000)]);
  const network = seams.fetch ?? globalThis.fetch;
  const json = async (url: string, authenticated = false) => {
    const response = await withAbort(fetchUpstream(network, url, { signal: bound, redirect: "error", headers: {
      accept: "application/json", "cache-control": "no-cache, no-store", ...(authenticated ? { authorization: `Bearer ${apiKey}` } : {}),
    } }, "evidence", "TEE_ATTESTATION_REJECTED"), bound);
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(response.body, 32 * 1024 * 1024, bound)));
  };
  try {
    // Resolve again even for a persisted Pi catalog; provider labels never authenticate a key.
    const catalog = await json(`${CHUTES_BASE_URL}/models`);
    if (!parseChutesCatalog(catalog).some(entry => entry.id === model)) throw new TeeError("TEE_MODEL_UNAVAILABLE");
    const chute = entries(catalog).find(entry => entry.id === model)!.chute_id as string;
    const discoveryAt = Date.now();
    const discovery = await json(`${CHUTES_API_URL}/e2e/instances/${chute}`, true);
    if (!Array.isArray(discovery.instances) || !discovery.instances.length || discovery.instances.length > 256 ||
      !Number.isFinite(discovery.nonce_expires_in) || discovery.nonce_expires_in <= 0) throw new TeeError("TEE_ATTESTATION_REJECTED");
    const invocationExpiry = discoveryAt + Math.min(discovery.nonce_expires_in, 55) * 1000;
    const challengeAt = Date.now();
    const nonce = randomBytes(32).toString("hex");
    const bundle = await json(`${CHUTES_API_URL}/chutes/${chute}/evidence?nonce=${nonce}`);
    if (!Array.isArray(bundle.evidence) || bundle.evidence.length > 256) throw new TeeError("TEE_ATTESTATION_REJECTED");
    const ids = bundle.evidence.map((entry: unknown) => record(entry).instance_id);
    if (new Set(ids).size !== ids.length) throw new TeeError("TEE_ATTESTATION_REJECTED");
    let chosen: { id: string; publicKey: string; token: string; security: RouteSecurity } | undefined;
    let rejected: RouteSecurity | undefined;
    const discoveredIds = new Set<string>();
    for (const value of discovery.instances) {
      bound.throwIfAborted();
      const item = record(value);
      const id = String(item.instance_id);
      if (!UUID.test(id) || discoveredIds.has(id)) throw new TeeError("TEE_ATTESTATION_REJECTED");
      discoveredIds.add(id);
      const evidence = bundle.evidence.find((entry: unknown) => record(entry).instance_id === id);
      if (!evidence || !Array.isArray(item.nonces) || typeof item.nonces[0] !== "string" || !/^[A-Za-z0-9_.:-]{1,4096}$/.test(item.nonces[0])) continue;
      const publicKey = String(item.e2e_pubkey);
      let rating: Awaited<ReturnType<typeof verifyChutesInstance>>;
      try { rating = await verifyChutesInstance(evidence, publicKey, nonce, bound, seams.cpu); }
      catch { bound.throwIfAborted(); continue; }
      const security: RouteSecurity = { route: "chutes-e2ee", provider: "Chutes", cpuVerified: true,
        code: 3, host: rating.host, gpu: 3, egress: 3,
        observed: [...rating.observed, `Selected instance ${id}; fresh nonce, ML-KEM-768 key and host TLS SPKI authenticated locally.`,
          "Reported GPUs do not establish the full serving set; GPU reports are not appraised and NRAS is not used."] };
      if (!assessRoute(policy, security).accepted) { rejected ??= security; continue; }
      if (!chosen || rating.host < chosen.security.host) chosen = { id, publicKey, token: item.nonces[0], security };
      if (rating.host === 1) break;
    }
    const expiresAt = Math.floor(Math.min(invocationExpiry, challengeAt + 60000));
    if (Date.now() >= expiresAt) throw new TeeError("TEE_PUBLIC_SESSION_REJECTED");
    if (!chosen) { if (rejected) throw new RouteRejection(rejected); throw new TeeError("TEE_ATTESTATION_REJECTED"); }
    const selected = chosen;
    const invoke = seams.invoke ?? chutesInvocationFetch(`${CHUTES_API_URL}/e2e/invoke`, expiresAt);
    let used = false;
    let responseSecret: Uint8Array | undefined;
    // The preflight deadline ends at dispatch. A live response instead follows caller cancellation.
    const responseBound = AbortSignal.any([signal, controller.signal]);
    return {
      security: selected.security, baseUrl: CHUTES_BASE_URL, expiresAt,
      dispose: () => { controller.abort(); responseSecret?.fill(0); },
      fetch: async (input, init) => {
        const request = new Request(input, init);
        const callSignal = AbortSignal.any([responseBound, request.signal]);
        callSignal.throwIfAborted();
        if (used || Date.now() >= expiresAt || request.url !== `${CHUTES_BASE_URL}/chat/completions` || request.method !== "POST") throw new TeeError("TEE_REQUEST_REJECTED");
        used = true;
        const bytes = await readBoundedBody(request.body, MAX_REQUEST_BYTES, callSignal);
        const payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
        if (payload.model !== model || payload.stream !== true) throw new TeeError("TEE_REQUEST_REJECTED");
        base64(selected.publicKey, 1184);
        const sealed = createE2eeRequest(selected.publicKey, payload);
        responseSecret = sealed.responseSecret;
        callSignal.throwIfAborted();
        if (Date.now() >= expiresAt) throw new TeeError("TEE_PUBLIC_SESSION_REJECTED");
        try {
          const response = await withAbort(fetchUpstream(invoke, `${CHUTES_API_URL}/e2e/invoke`, {
            method: "POST", body: new Uint8Array(sealed.body), signal: callSignal, redirect: "error",
            headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/octet-stream",
              "X-Chute-Id": chute, "X-Instance-Id": selected.id, "X-E2E-Nonce": selected.token,
              "X-E2E-Stream": "true", "X-E2E-Path": "/v1/chat/completions" },
          }, "request", "TEE_RESPONSE_REJECTED"), callSignal);
          return decryptE2eeStream(response, sealed.responseSecret, callSignal);
        } catch (error) { responseSecret.fill(0); controller.abort(); throw error; }
      },
    };
  } catch (error) { controller.abort(); throw error; }
}
