import { authenticateResponse, TeeError, withAbort, type SdkTransport } from "pi-tee-core";
import { NearDirectChannel } from "./direct-channel.js";

export const NEAR_DIRECT_PROFILE = {
  model: "z-ai/glm-5.3-flash",
  baseUrl: "https://glm-5-3-flash.completions.near.ai/v1",
} as const;

export async function openDirectNearTransport(apiKey: string, signal: AbortSignal): Promise<SdkTransport> {
  const { DirectAttestationClient, DirectInferenceClient } = await import("@nearai/inference-sdk/node");
  signal.throwIfAborted();
  const baseUrl = NEAR_DIRECT_PROFILE.baseUrl;
  const channel = new NearDirectChannel(new URL(baseUrl).origin, signal);
  class BoundEvidence extends DirectAttestationClient {
    override fetchModelAttestations() {
      return this.fetchModelAttestationsWithOptions({ signingAlgo: "ed25519", includeSpkiFingerprint: true });
    }
    protected override requestAttestation(request: Request) { return channel.request(request); }
    protected override requestApi(request: Request) {
      request.headers.set("authorization", `Bearer ${apiKey}`);
      return channel.fetch(request);
    }
  }
  const evidence = new BoundEvidence({ baseUrl: `${baseUrl}/` });
  class BoundInference extends DirectInferenceClient {
    protected override fetchModelAttestations() { return evidence.fetchModelAttestations(); }
    protected override createDirectSessionTransport({ tlsBinding }: {
      tlsBinding: import("@nearai/inference-sdk/node").DirectTlsBinding;
      attestations: readonly import("@nearai/inference-sdk/node").VerifiedDirectModelAttestation[];
    }) {
      if (tlsBinding.kind !== "attested") throw new TeeError("TEE_TLS_KEY_REJECTED");
      channel.approve(tlsBinding.spkiFingerprint);
      return { fetch: channel.fetch, fetchCompletionSignature: (params: import("@nearai/inference-sdk/node").FetchCompletionSignatureParams) => evidence.fetchCompletionSignature(params) };
    }
  }
  const client = new BoundInference({
    apiKey, baseUrl: `${baseUrl}/`, signingAlgo: "ed25519", e2ee: true, ohttp: true,
    attestationCacheTimeToLiveMs: 0, responseCacheTimeToLiveMs: 60_000,
    modelVerification: { policy: { acceptedTcbStatuses: ["UpToDate"], gpuEvidence: "required" } },
  });
  signal.throwIfAborted();
  return {
    baseUrl, dispose: () => channel.close(),
    fetch: async (input, init) => {
      const controller = new AbortController();
      const request = new Request(input, init);
      const bound = AbortSignal.any([signal, request.signal, controller.signal]);
      const response = await withAbort(client.fetch(new Request(request, { signal: bound })), bound);
      return authenticateResponse(response, {
        signal: bound, cancel: () => { controller.abort(); channel.close(); },
        verify: async id => {
          const result = await client.verifyResponse(id);
          if (result.signatureKind !== "provider_tee") throw new TeeError("TEE_RESPONSE_REJECTED");
        },
      });
    },
  };
}
