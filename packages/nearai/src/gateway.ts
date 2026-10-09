import { authenticateResponse, TeeError, withAbort, type runNvidiaVerifier, type RouteSecurity, type SdkTransport } from "pi-tee-core";
import { NEAR_BASE_URL } from "./catalog.js";
import { createNearCpuVerifier, type NearHostRating } from "./cpu.js";
import { NearDirectChannel } from "./direct-channel.js";
import { nearModelVerification, observeNearGpuEvidence } from "./gpu.js";

export interface NearGatewaySeams {
  cpu?: Pick<Parameters<typeof createNearCpuVerifier>[0], "collateral" | "verify">;
  channel?: Pick<NearDirectChannel, "request" | "fetch" | "approve" | "close">;
  runNvidiaVerifier?: typeof runNvidiaVerifier;
}

/**
 * The SDK's gateway protocol on one owned socket: the TLS key the gateway quote binds is the
 * connection that carries model evidence, the sealed request and its signature.
 */
export async function openNearGatewayTransport(apiKey: string, signal: AbortSignal, model: string, seams: NearGatewaySeams = {}): Promise<SdkTransport & { security: RouteSecurity }> {
  const { AttestationClient, InferenceClient } = await import("@nearai/inference-sdk/node");
  signal.throwIfAborted();
  const channel = seams.channel ?? new NearDirectChannel(new URL(NEAR_BASE_URL).origin, signal, {}, { gatewayModel: model });
  const ratings: NearHostRating[] = [], observed: string[] = [];
  const tdxQuote = createNearCpuVerifier({ ...seams.cpu, signal, onRating: rating => ratings.push(rating) });
  class ChannelEvidence extends AttestationClient {
    protected override requestGatewayAttestation(request: Request) { return channel.request(request); }
  }
  const evidence = new ChannelEvidence({ apiKey, baseUrl: `${NEAR_BASE_URL}/` });
  let peer: string | undefined;
  class ChannelInferenceClient extends InferenceClient {
    protected override fetchGatewayAttestation() {
      return evidence.fetchGatewayAttestation({ signingAlgo: "ed25519", includeSpkiFingerprint: true });
    }
    protected override createGatewayFetch(fingerprint?: string): typeof globalThis.fetch {
      if (!fingerprint || (peer !== undefined && fingerprint !== peer)) throw new TeeError("TEE_TLS_KEY_REJECTED");
      peer = fingerprint;
      return async (input, init) => {
        const request = new Request(input, init);
        const response = await channel.fetch(request);
        const url = new URL(request.url);
        if (url.pathname === "/v1/attestation/report" && url.searchParams.has("model") && response.ok) {
          const data = await response.json() as { model_attestations?: Record<string, unknown>[] };
          if (Array.isArray(data.model_attestations)) for (const attestation of data.model_attestations) {
            if (typeof attestation.nvidia_payload === "string") observed.push(...await observeNearGpuEvidence(attestation.nvidia_payload, url.searchParams.get("nonce")!, { signal, run: seams.runNvidiaVerifier }));
            // GPU coverage is unknown. Preserve the CPU evidence; do not let GPU diagnostics gate G3.
            delete attestation.nvidia_payload;
          }
          return Response.json(data, { status: response.status });
        }
        return response;
      };
    }
  }
  const client = new ChannelInferenceClient({
    apiKey, baseUrl: `${NEAR_BASE_URL}/`, signingAlgo: "ed25519", e2ee: true, ohttp: true,
    attestationCacheTimeToLiveMs: 300_000, responseCacheTimeToLiveMs: 60_000,
    gatewayVerification: { includeSpkiFingerprint: true, policy: { acceptedTcbStatuses: ["UpToDate", "OutOfDate"] }, verifiers: { tdxQuote } },
    modelVerification: nearModelVerification(tdxQuote),
  });
  const challengeAt = Date.now();
  try {
    await withAbort(client.verify(model), signal);
    signal.throwIfAborted();
    if (ratings.length < 2 || !peer) throw new TeeError("TEE_CPU_POLICY_REJECTED");
    channel.approve(peer);
  } catch (error) { channel.close(); throw error; }
  return {
    security: { route: "near-gateway", provider: "NEAR", cpuVerified: true, code: 3, host: ratings.some(r => r.host === 2) ? 2 : 1, gpu: 3, egress: 3,
      observed: [...new Set([...ratings.flatMap(r => r.observed), ...observed,
        "Gateway evidence, model evidence, the sealed request and its signature share one TLS connection to the quote-bound key; gateway replicas share that key, so it does not identify one serving instance",
        "Gateway CVM serves on CPU only; model-worker GPU coverage remains unknown", "NEAR commitments: no-training terms; no contractual zero-retention; deployed transcript retention is unverified"])],
    },
    expiresAt: challengeAt + 300_000, dispose: () => channel.close(),
    fetch: async (input, init) => {
      const controller = new AbortController();
      const request = new Request(input, init);
      const bound = AbortSignal.any([signal, request.signal, controller.signal]);
      const response = await withAbort(client.fetch(new Request(request, { signal: bound })), bound);
      return authenticateResponse(response, { signal: bound, cancel: () => { controller.abort(); channel.close(); }, verify: async id => {
        if ((await client.verifyResponse(id)).signatureKind !== "provider_tee") throw new TeeError("TEE_RESPONSE_REJECTED");
      } });
    },
  };
}
