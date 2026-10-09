import { authenticateResponse, limitResponseBody, MAX_ENCRYPTED_RESPONSE_BYTES, TeeError, withAbort, type RouteSecurity, type SdkTransport } from "pi-tee-core";
import { NEAR_BASE_URL } from "./catalog.js";
import { createNearCpuVerifier, type NearHostRating } from "./cpu.js";
import { observeNearGpuEvidence } from "./gpu.js";

export async function openNearGatewayTransport(apiKey: string, signal: AbortSignal, model: string): Promise<SdkTransport & { security: RouteSecurity }> {
  if (process.versions.bun || Number(process.versions.node.split(".")[0]) < 24) throw new TeeError("TEE_RUNTIME_UNSUPPORTED");
  const { InferenceClient } = await import("@nearai/inference-sdk/node");
  const ratings: NearHostRating[] = [], observed: string[] = [];
  const tdxQuote = createNearCpuVerifier({ signal, onRating: rating => ratings.push(rating) });
  class BoundedInferenceClient extends InferenceClient {
    protected override createPinnedTlsFetch(fingerprint: string): typeof globalThis.fetch {
      const pinned = super.createPinnedTlsFetch(fingerprint);
      return async (input, init) => {
        const request = new Request(input, init);
        const controller = new AbortController();
        const bound = AbortSignal.any([signal, request.signal, controller.signal]);
        const response = limitResponseBody(await withAbort(pinned(new Request(request, { signal: bound })), bound), {
          signal: bound, maxBytes: MAX_ENCRYPTED_RESPONSE_BYTES, cancel: () => controller.abort(),
        });
        const url = new URL(request.url);
        if (url.pathname === "/v1/attestation/report" && url.searchParams.has("model") && response.ok) {
          const data = await response.json() as { model_attestations?: Record<string, unknown>[] };
          if (Array.isArray(data.model_attestations)) for (const attestation of data.model_attestations) {
            if (typeof attestation.nvidia_payload === "string") observed.push(...await observeNearGpuEvidence(attestation.nvidia_payload, url.searchParams.get("nonce")!, { signal: bound }));
            // GPU coverage is unknown. Preserve the CPU evidence; do not let GPU diagnostics gate G3.
            delete attestation.nvidia_payload;
          }
          return Response.json(data, { status: response.status });
        }
        return response;
      };
    }
  }
  const client = new BoundedInferenceClient({
    apiKey, baseUrl: `${NEAR_BASE_URL}/`, signingAlgo: "ed25519", e2ee: true, ohttp: true,
    attestationCacheTimeToLiveMs: 300_000, responseCacheTimeToLiveMs: 60_000,
    gatewayVerification: { includeSpkiFingerprint: true, policy: { acceptedTcbStatuses: ["UpToDate", "OutOfDate"] }, verifiers: { tdxQuote } },
    modelVerification: { policy: { acceptedTcbStatuses: ["UpToDate", "OutOfDate"], gpuEvidence: "if-present" }, verifiers: { tdxQuote } },
  });
  const challengeAt = Date.now();
  await withAbort(client.verify(model), signal);
  if (ratings.length < 2) throw new TeeError("TEE_CPU_POLICY_REJECTED");
  return {
    security: { route: "near-gateway", provider: "NEAR", cpuVerified: true, code: 3, host: ratings.some(r => r.host === 2) ? 2 : 1, gpu: 3, egress: 3,
      observed: [...new Set([...ratings.flatMap(r => r.observed), ...observed, "Gateway CVM serves on CPU only; model-worker GPU coverage remains unknown", "NEAR commitments: no-training terms; no contractual zero-retention; deployed transcript retention is unverified"])],
    },
    expiresAt: challengeAt + 300_000,
    fetch: async (input, init) => {
      const controller = new AbortController();
      const request = new Request(input, init);
      const bound = AbortSignal.any([signal, request.signal, controller.signal]);
      const response = await withAbort(client.fetch(new Request(request, { signal: bound })), bound);
      return authenticateResponse(response, { signal: bound, cancel: () => controller.abort(), verify: async id => {
        if ((await client.verifyResponse(id)).signatureKind !== "provider_tee") throw new TeeError("TEE_RESPONSE_REJECTED");
      } });
    },
  };
}
