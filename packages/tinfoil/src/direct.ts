import { randomBytes } from "node:crypto";
import {
  limitResponseBody, MAX_ENCRYPTED_RESPONSE_BYTES, MAX_RESPONSE_BYTES,
  pinnedTlsFetch, readBoundedBody, TeeError, withAbort, type SdkTransport,
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
  const { Identity } = await import("ehbp");
  const identity = await Identity.fromPublicKeyHex(attestation.hpkePublicKey);
  const baseUrl = `https://${profile.host}/v1`;
  const endpoint = `${baseUrl}/chat/completions`;
  const fetch = pinnedTlsFetch(endpoint, attestation.tlsPublicKeyFingerprint);
  const cacheSecret = randomBytes(32).toString("hex");
  return { baseUrl, fetch: async (input, init) => {
    const request = new Request(input, init);
    if (request.url !== endpoint || request.method !== "POST") throw new TeeError("TEE_REQUEST_REJECTED");
    const requestSignal = AbortSignal.any([signal, request.signal]);
    requestSignal.throwIfAborted();
    // The shared provider checked the payload. Provision a generated, encrypted cache field.
    const body = { ...await request.json(), user_cache_secret: cacheSecret };
    const encrypted = await identity.encryptRequestWithContext(new Request(endpoint, {
      method: "POST", headers: request.headers, body: JSON.stringify(body), signal: requestSignal,
    }));
    if (!encrypted.context) throw new TeeError("TEE_REQUEST_REJECTED");
    const wire = await fetch(encrypted.request);
    if (wire.status !== 200) {
      await wire.body?.cancel();
      // Rotation/auth/error responses never trigger re-attestation or a second prompt send.
      throw new TeeError("TEE_RESPONSE_REJECTED");
    }
    const bounded = limitResponseBody(wire, { signal: requestSignal, maxBytes: MAX_ENCRYPTED_RESPONSE_BYTES });
    const plaintext = await identity.decryptResponseWithContext(bounded, encrypted.context);
    return limitResponseBody(plaintext, { signal: requestSignal, maxBytes: MAX_RESPONSE_BYTES });
  } };
}
