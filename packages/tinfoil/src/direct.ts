import { randomBytes } from "node:crypto";
import {
  limitResponseBody, MAX_ENCRYPTED_RESPONSE_BYTES, MAX_RESPONSE_BYTES,
  pinnedTlsFetch, webPkiTlsFetch, readBoundedBody, TeeError, withAbort, type SdkTransport,
} from "pi-tee-core";
import type { AttestationBundle } from "tinfoil";

// A fixed research candidate, not independent workload approval.
export const TINFOIL_DIRECT_PROFILE = Object.freeze({
  host: "gemma4-31b-inf6-3.tinfoil.containers.tinfoil.dev",
  repo: "tinfoilsh/confidential-gemma4-31b",
  model: "gemma4-31b",
  tag: "v0.0.25",
  digest: "65f2dfa59ced010aeba841fc909880ac3434282cf2b43e90d5c3a3e543b3ccf0",
  measurement: "42fbc892c9ad2446f82571b5bf1b9de153af87c0c8a63dad1e6f20e9ece0c77ab8380d7e426cab5e32b9b6f73db2febf",
});

export async function openDirectTinfoilTransport(signal: AbortSignal, attestationFetch: typeof globalThis.fetch = globalThis.fetch): Promise<SdkTransport> {
  signal.throwIfAborted();
  const profile = TINFOIL_DIRECT_PROFILE;
  const response = await attestationFetch("https://atc.tinfoil.sh/attestation", {
    method: "POST", signal, redirect: "error", headers: { "content-type": "application/json" },
    body: JSON.stringify({ enclaveUrl: `https://${profile.host}`, repo: profile.repo }),
  });
  if (!response.ok) throw new TeeError("TEE_ATTESTATION_REJECTED");
  const bundle = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(response.body, 2 * 1024 * 1024, signal))) as AttestationBundle;
  if (bundle.domain !== profile.host || bundle.digest !== profile.digest || (bundle.releaseTag !== undefined && bundle.releaseTag !== profile.tag)) throw new TeeError("TEE_WORKLOAD_PIN_REJECTED");
  const { Verifier } = await import("tinfoil");
  const verifier = new Verifier({ configRepo: profile.repo });
  const attestation = await withAbort(verifier.verifyBundle(bundle), signal);
  if (verifier.getVerificationDocument()?.releaseTag !== profile.tag || attestation.measurement.type !== "https://tinfoil.sh/predicate/sev-snp-guest/v2" ||
      attestation.measurement.registers.length !== 1 || attestation.measurement.registers[0] !== profile.measurement ||
      !attestation.tlsPublicKeyFingerprint || !attestation.hpkePublicKey) throw new TeeError("TEE_WORKLOAD_PIN_REJECTED");
  signal.throwIfAborted();
  return openEncryptedWorkerTransport(signal, profile.host, { tls: attestation.tlsPublicKeyFingerprint, hpke: attestation.hpkePublicKey }, "user_cache_secret");
}

// `logicalBaseUrl` lets a profile with discovered workers keep one canonical
// endpoint: callers address it, and only this transport's attested host is dialed.
export async function openEncryptedWorkerTransport(signal: AbortSignal, host: string, keys: { tls: string; hpke: string }, cacheField: "user_cache_secret" | "cache_salt", expiresAt?: number, logicalBaseUrl?: string): Promise<SdkTransport> {
  const endpoint = `https://${host}/v1/chat/completions`;
  return openEncryptedTransport(signal, keys.hpke, endpoint, logicalBaseUrl ?? `https://${host}/v1`, cacheField, pinnedTlsFetch(endpoint, keys.tls, expiresAt), expiresAt);
}

export const GATEWAY_MODELS = Object.freeze(["deepseek-v4-1-flash", "glm-5-3"] as const);
export const TINFOIL_GATEWAY_BASE_URL = "https://inference-gateway.tinfoil.sh/v1";

/** One sealed dispatch; a 412 or any other error is terminal, with no resend. */
export async function openEncryptedGatewayTransport(signal: AbortSignal, host: string, keys: { hpke: string }, model: string, expiresAt: number, wireFetch?: typeof globalThis.fetch): Promise<SdkTransport> {
  if (!/^[a-z0-9-]+-inf[0-9]+(?:-[0-9]+)?\.tinfoil\.containers\.tinfoil\.dev$/.test(host) ||
      !GATEWAY_MODELS.some(allowed => model === allowed)) throw new TeeError("TEE_REQUEST_REJECTED");
  const endpoint = `${TINFOIL_GATEWAY_BASE_URL}/chat/completions`;
  return openEncryptedTransport(signal, keys.hpke, endpoint, TINFOIL_GATEWAY_BASE_URL, "cache_salt", wireFetch ?? webPkiTlsFetch(endpoint, expiresAt), expiresAt, {
    "x-tinfoil-seal": host, "x-tinfoil-model": model, "x-tinfoil-enclave-url": `https://${host}`,
  });
}

async function openEncryptedTransport(signal: AbortSignal, hpke: string, endpoint: string, baseUrl: string, cacheField: "user_cache_secret" | "cache_salt", fetch: typeof globalThis.fetch, expiresAt?: number, routingHeaders?: Record<string, string>): Promise<SdkTransport> {
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
    const body = { ...await request.json(), [cacheField]: cacheSecret };
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
