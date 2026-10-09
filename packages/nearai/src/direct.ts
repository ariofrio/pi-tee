import { authenticateResponse, TeeError, withAbort, type runNvidiaVerifier, type SdkTransport, type RouteSecurity } from "pi-tee-core";
import { createNearCpuVerifier, type NearHostRating } from "./cpu.js";
import { NearDirectChannel } from "./direct-channel.js";
import { nearModelVerification, observeNearGpuEvidence } from "./gpu.js";
import { NEAR_DIRECT_HOST } from "./discovery.js";

export interface NearDirectTarget { model: string; hostname: string }

export async function openDirectNearTransport(apiKey: string, signal: AbortSignal, target: NearDirectTarget, seams: {
  cpu?: Pick<Parameters<typeof createNearCpuVerifier>[0], "collateral" | "verify">;
  channel?: Pick<NearDirectChannel, "request" | "fetch" | "approve" | "close">;
  runNvidiaVerifier?: typeof runNvidiaVerifier;
} = {}): Promise<SdkTransport & { security: RouteSecurity }> {
  if (!NEAR_DIRECT_HOST.test(target.hostname)) throw new TeeError("TEE_REQUEST_REJECTED");
  const { DirectAttestationClient, DirectInferenceClient } = await import("@nearai/inference-sdk/node");
  signal.throwIfAborted();
  const baseUrl = `https://${target.hostname}/v1`;
  const channel = seams.channel ?? new NearDirectChannel(new URL(baseUrl).origin, signal);
  // GPU reports provide optional local status details; NEAR remains G3.
  const hostRatings: NearHostRating[] = [];
  const observed: string[] = [];
  const tdxQuote = createNearCpuVerifier({ ...seams.cpu, signal, onRating: rating => hostRatings.push(rating) });
  const appraisals = new Map<string, Promise<string[]>>();
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
    protected override async fetchModelAttestations() {
      const fetched = await evidence.fetchModelAttestations();
      if (fetched.servingAttestation.modelName !== target.model || fetched.attestations.some(attestation => attestation.modelName !== target.model)) {
        throw new TeeError("TEE_MODEL_ATTESTATION_UNAVAILABLE");
      }
      const strip = async (attestation: typeof fetched.servingAttestation) => {
        const { nvidiaPayload, ...cpuEvidence } = attestation;
        if (nvidiaPayload) {
          let appraisal = appraisals.get(nvidiaPayload);
          if (!appraisal) appraisals.set(nvidiaPayload, appraisal = observeNearGpuEvidence(nvidiaPayload, fetched.clientBinding.nonce, { signal, run: seams.runNvidiaVerifier }));
          observed.push(...await appraisal);
        }
        return cpuEvidence;
      };
      return { ...fetched, servingAttestation: await strip(fetched.servingAttestation), attestations: await Promise.all(fetched.attestations.map(strip)) };
    }
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
    attestationCacheTimeToLiveMs: 300_000, responseCacheTimeToLiveMs: 60_000,
    modelVerification: nearModelVerification(tdxQuote),
  });
  const challengeAt = Date.now();
  try {
    await withAbort(client.verify(target.model), signal);
    signal.throwIfAborted();
    if (!hostRatings.length) throw new TeeError("TEE_CPU_POLICY_REJECTED");
  } catch (error) { channel.close(); throw error; }
  return {
    security: { route: "near-direct", provider: "NEAR", cpuVerified: true, code: 3,
      host: hostRatings.some(r => r.host === 2) ? 2 : 1, gpu: 3, egress: 3,
      observed: [...new Set([`Direct endpoint: ${target.hostname}; model: ${target.model}.`, ...hostRatings.flatMap(r => r.observed), ...observed, "Shared NEAR endpoint and response keys do not identify exclusive serving-instance custody"])],
    },
    baseUrl, expiresAt: challengeAt + 300_000, dispose: () => channel.close(),
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
