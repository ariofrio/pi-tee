import { randomBytes } from "node:crypto";
import {
  limitResponseBody, MAX_ENCRYPTED_RESPONSE_BYTES, MAX_RESPONSE_BYTES,
  pinnedTlsFetch, webPkiTlsFetch, TeeError, type SdkTransport,
} from "pi-tee-core";

// `logicalBaseUrl` lets a profile with discovered workers keep one canonical
// endpoint: callers address it, and only this transport's attested host is dialed.
export async function openEncryptedWorkerTransport(signal: AbortSignal, host: string, keys: { tls: string; hpke: string }, expiresAt?: number, logicalBaseUrl?: string, wireFetch?: typeof globalThis.fetch): Promise<SdkTransport> {
  const endpoint = `https://${host}/v1/chat/completions`;
  return openEncryptedTransport(signal, keys.hpke, endpoint, logicalBaseUrl ?? `https://${host}/v1`, wireFetch ?? pinnedTlsFetch(endpoint, keys.tls, expiresAt), expiresAt);
}

export const GATEWAY_MODELS = Object.freeze(["deepseek-v4-1-flash", "glm-5-3"] as const);
export const TINFOIL_GATEWAY_BASE_URL = "https://inference-gateway.tinfoil.sh/v1";

/** One sealed dispatch; a 412 or any other error is terminal, with no resend. */
export async function openEncryptedGatewayTransport(signal: AbortSignal, host: string, keys: { hpke: string }, model: string, expiresAt: number, wireFetch?: typeof globalThis.fetch): Promise<SdkTransport> {
  if (!/^[a-z0-9-]+-inf[0-9]+(?:-[0-9]+)?\.tinfoil\.containers\.tinfoil\.dev$/.test(host) ||
      !GATEWAY_MODELS.some(allowed => model === allowed)) throw new TeeError("TEE_REQUEST_REJECTED");
  const endpoint = `${TINFOIL_GATEWAY_BASE_URL}/chat/completions`;
  return openEncryptedTransport(signal, keys.hpke, endpoint, TINFOIL_GATEWAY_BASE_URL, wireFetch ?? webPkiTlsFetch(endpoint, expiresAt), expiresAt, {
    "x-tinfoil-seal": host, "x-tinfoil-model": model, "x-tinfoil-enclave-url": `https://${host}`,
  });
}

async function openEncryptedTransport(signal: AbortSignal, hpke: string, endpoint: string, baseUrl: string, fetch: typeof globalThis.fetch, expiresAt?: number, routingHeaders?: Record<string, string>): Promise<SdkTransport> {
  const { Identity } = await import("ehbp");
  const identity = await Identity.fromPublicKeyHex(hpke);
  const addressed = `${baseUrl}/chat/completions`;
  // A fresh encrypted salt isolates this dispatch's cache namespace. Reusing it
  // across turns could correlate prompts; fresh salts sacrifice prefix-cache hits.
  const cacheSecret = randomBytes(32).toString("hex");
  let sent = false;
  return { baseUrl, fetch: async (input, init) => {
    const request = new Request(input, init);
    if (request.url !== addressed || request.method !== "POST" || sent) throw new TeeError("TEE_REQUEST_REJECTED");
    sent = true;
    const requestSignal = AbortSignal.any([signal, request.signal]);
    requestSignal.throwIfAborted();
    if (expiresAt !== undefined && Date.now() >= expiresAt) throw new TeeError("TEE_PUBLIC_SESSION_REJECTED");
    // The shared provider checked the payload. Provision a generated, encrypted cache field.
    const body = { ...await request.json(), cache_salt: cacheSecret };
    if (routingHeaders && body.model !== routingHeaders["x-tinfoil-model"]) throw new TeeError("TEE_REQUEST_REJECTED");
    const headers = new Headers(request.headers);
    for (const [name, value] of Object.entries(routingHeaders ?? {})) headers.set(name, value);
    const encrypted = await identity.encryptRequestWithContext(new Request(endpoint, {
      method: "POST", headers, body: JSON.stringify(body), signal: requestSignal,
    }));
    if (!encrypted.context) throw new TeeError("TEE_REQUEST_REJECTED");
    const wire = await fetch(encrypted.request);
    if (wire.status !== 200) {
      await wire.body?.cancel();
      // Rotation/auth/error responses never trigger re-attestation or a second prompt send.
      throw new TeeError("TEE_RESPONSE_REJECTED");
    }
    const bounded = limitResponseBody(wire, { signal: requestSignal, maxBytes: MAX_ENCRYPTED_RESPONSE_BYTES });
    if (!wire.body || !wire.headers.get("ehbp-response-nonce")) {
      await bounded.body?.cancel();
      throw new TeeError("TEE_RESPONSE_REJECTED");
    }
    let plaintext: Response;
    try { plaintext = await identity.decryptResponseWithContext(bounded, encrypted.context); }
    catch { await bounded.body?.cancel(); throw new TeeError("TEE_RESPONSE_REJECTED"); }
    return limitResponseBody(plaintext, { signal: requestSignal, maxBytes: MAX_RESPONSE_BYTES });
  } };
}
