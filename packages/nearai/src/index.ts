import {
  authenticateResponse, createTeeProvider, limitResponseBody, MAX_ENCRYPTED_RESPONSE_BYTES, resolveModelVisibility, resolvePolicy, TeeError, withAbort,
  type ModelVisibility, type PolicyMode, type ProviderDefinition,
} from "pi-tee-core";
import { NEAR_BASE_URL } from "./catalog.js";
import { loadNearCatalog } from "./discovery.js";
import { openDirectNearTransport, NEAR_DIRECT_PROFILE } from "./direct.js";
export { NEAR_BASE_URL, parseNearCatalog } from "./catalog.js";

export const NEAR_ASSUMPTIONS = [
  "Local Pi, runtime, extensions, tools and the pinned NEAR SDK are trusted.",
  "Intel quote validation and NVIDIA's remote verdict/JWKS policy are accepted; full guest-image appraisal and CPU–GPU channel binding are not established.",
  "NEAR gateway/model release, key-service, shared-key recipient and runtime deployment authorities remain trusted under SDK policy.",
  "Gateway TLS binding, OHTTP and model field encryption follow the SDK protocol; serving-instance identity is not established.",
  "A model-signed response is required before any completion or tool call is exposed; its shared signer does not identify one approved serving instance.",
  "Model assets, runtime downloads, mutation controls and deployment provenance have no independent approval in this mode.",
];

export function assertNearRuntime() {
  if (process.versions.bun || Number(process.versions.node.split(".")[0]) < 24) throw new TeeError("TEE_RUNTIME_UNSUPPORTED");
}

export function createNearProvider(options: {
  policy?: PolicyMode;
  route?: "gateway" | "direct";
  modelVisibility?: ModelVisibility;
  catalogFetch?: typeof globalThis.fetch;
  openSdkTransport?: ProviderDefinition["openSdkTransport"];
} = {}) {
  const route = options.route ?? process.env.PI_NEARAI_ROUTE ?? "gateway";
  if (route !== "gateway" && route !== "direct") throw new TeeError("TEE_ROUTE_INVALID");
  const assumptions = route === "direct" ? [
    "Local Pi, runtime, extensions, tools and the pinned NEAR SDK are trusted.",
    "Experimental direct mode requires UpToDate Intel evidence and NVIDIA remote GPU verdicts, with OHTTP and model field encryption.",
    "Evidence, credentials, encrypted inference and signature retrieval use one WebPKI-authenticated TLS socket with quote-bound SPKI approval; reconnect and resend are rejected.",
    "NEAR shared TLS keys still permit evidence relay by another key holder; the shared response signer does not identify a single approved instance.",
    "Guest images, CPU–GPU channel binding, key service, runtime mutation controls and model artifacts lack independent qualification.",
  ] : NEAR_ASSUMPTIONS;
  return createTeeProvider({
    id: "nearai", name: "NEAR AI", baseUrl: NEAR_BASE_URL, apiKeyEnv: "NEARAI_API_KEY",
    policy: options.policy ?? resolvePolicy(process.env.PI_NEARAI_POLICY),
    modelVisibility: options.modelVisibility ?? resolveModelVisibility(process.env.PI_NEARAI_MODEL_VISIBILITY),
    parseCatalog: loadNearCatalog, requireDeclaredTee: true, catalogFetch: options.catalogFetch, assumptions,
    availableModelIds: route === "direct" ? [NEAR_DIRECT_PROFILE.model] : undefined,
    openSdkTransport: options.openSdkTransport ?? (route === "direct" ? async ({ apiKey, signal }) => {
      assertNearRuntime();
      return openDirectNearTransport(apiKey, signal);
    } : async ({ apiKey, signal }) => {
      assertNearRuntime();
      const { TLSSocket } = await import("node:tls");
      if (typeof TLSSocket.prototype.getPeerCertificate !== "function" || typeof TLSSocket.prototype.getPeerX509Certificate !== "function") {
        throw new TeeError("TEE_RUNTIME_UNSUPPORTED");
      }
      const { InferenceClient } = await import("@nearai/inference-sdk/node");
      signal.throwIfAborted();
      class BoundedInferenceClient extends InferenceClient {
        protected override createPinnedTlsFetch(fingerprint: string): typeof globalThis.fetch {
          const pinned = super.createPinnedTlsFetch(fingerprint);
          return async (input, init) => {
            const request = new Request(input, init);
            const controller = new AbortController();
            const bound = AbortSignal.any([signal, request.signal, controller.signal]);
            const response = await withAbort(pinned(new Request(request, { signal: bound })), bound);
            // Bound ciphertext before OHTTP decoding and the SDK's retained signature record.
            return limitResponseBody(response, {
              signal: bound, maxBytes: MAX_ENCRYPTED_RESPONSE_BYTES, cancel: () => controller.abort(),
            });
          };
        }
      }
      const client = new BoundedInferenceClient({
        apiKey, baseUrl: `${NEAR_BASE_URL}/`, signingAlgo: "ed25519", e2ee: true, ohttp: true,
        attestationCacheTimeToLiveMs: 0, responseCacheTimeToLiveMs: 60_000,
        gatewayVerification: { includeSpkiFingerprint: true, policy: { acceptedTcbStatuses: ["UpToDate"] } },
        modelVerification: { policy: { acceptedTcbStatuses: ["UpToDate"], gpuEvidence: "required" } },
      });
      return { fetch: async (input, init) => {
        const controller = new AbortController();
        const request = new Request(input, init);
        const bound = AbortSignal.any([signal, request.signal, controller.signal, AbortSignal.timeout(600_000)]);
        const response = await withAbort(client.fetch(new Request(request, { signal: bound })), bound);
        return authenticateResponse(response, {
          signal: bound, cancel: () => controller.abort(),
          verify: async (id) => {
            const result = await client.verifyResponse(id);
            if (result.signatureKind !== "provider_tee") throw new TeeError("TEE_RESPONSE_REJECTED");
          },
        });
      } };
    }),
  });
}
