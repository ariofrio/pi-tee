import { AsyncLocalStorage } from "node:async_hooks";
import { createHash } from "node:crypto";
import {
  createTeeProvider,
  resolvePolicy,
  TeeError,
  type PolicyMode,
} from "pi-tee-core";
import {
  privatemodeCatalog,
  PRIVATEMODE_MODELS,
  SHIPPED_CATALOG,
} from "./catalog.js";
import {
  manifestPolicyFromEnvironment,
  manifestRecorder,
  type ManifestAdmissionPolicy,
  type AdmittedManifest,
} from "./manifest.js";
import { openPrivatemodeTransport } from "./transport.js";
import { PRIVATEMODE_BASE_URL } from "./wire.js";
export {
  createPinnedManifestPolicy,
  createRecordedCdnManifestPolicy,
  manifestRecorder,
  MANIFEST_SHA256,
  type ManifestAdmissionPolicy,
} from "./manifest.js";
export { PRIVATEMODE_MODELS } from "./catalog.js";
export const PRIVATEMODE_ASSUMPTIONS = [
  "Trust: local Pi/runtime/extensions/tools and hash-pinned Privatemode 1.58.0 SDK/WASM; Intel, AMD and NVIDIA as manufacturers; Privatemode and its serving hosts.",
  "A2/H3/G3/X3: locally admitted exact manifest; Coordinator state and mesh CA authenticated freshly per request; workers' freshness/floors and complete GPU coverage are unverified. Observed Coordinator SNP build 1 is below pi-tee's Genoa minimum 21; no H1 claim.",
  "WebPKI gateway api.privatemode.ai sees Authorization: Bearer API key, paths, model (Privatemode-Target-Model), salted prefix shard keys, estimated token length when supplied, client/version, user request ID, secret ID and OAE public headers; ciphertext length, timing and IP address. The complete chat JSON body, tools, reasoning and stream response body are encrypted.",
  "Bootstrap also exposes a fresh random nonce, attestation evidence, manifest/policy hashes, mesh certificates, client ephemeral public key and encapsulated key/signature. Intel/AMD collateral services see certificate identifiers and timing, with no API credential or content.",
  "Plaintext/key recipients: local client; manifest-admitted secret service, inference proxies and engines, GPU devices and other admitted workloads able to obtain the shared deployment secret. Source-reviewed Coordinator admission, key custody, recovery, telemetry and storage behavior remain unverified at A2; weakest component counts.",
  "X3: container logs are operator-readable; the OTLP relay forwards raw bodies to an unattested collector without a payload-field allowlist. Content-free egress and plaintext-free storage are not verified.",
  "Manifest modes: hard-pin rejects every changed manifest; explicit logged-cdn authorizes newly fetched CDN bytes only after saving their change record. The SDK never re-fetches on mismatch. No proxyless API, NRAS, rotation refresh, redirect or inference resend. Pi tools/extensions and other providers remain outside this provider's boundary.",
  "Catalog starts from the shipped tool-chat snapshot. Credentialed native refresh filters live /v1/models to the three admitted model IDs; catalog claims never raise levels. Prices are unavailable; Reasoning-off/minimal maps to low for these effort-only models; GLM medium/high maps to high.",
  "Provider retention, training and audit commitments have not been appraised and never gate admission. Physical host attacks are outside the model.",
];
export function createPrivatemodeProvider(
  options: {
    policy?: PolicyMode;
    manifestPolicy?: ManifestAdmissionPolicy;
    admissionLog?: string;
    recordAdmission?: (
      manifest: AdmittedManifest,
      signal: AbortSignal,
    ) => Promise<void>;
    networkFetch?: typeof globalThis.fetch;
  } = {},
) {
  const record =
    options.recordAdmission ?? manifestRecorder(options.admissionLog);
  const admissionPolicy =
    options.manifestPolicy ?? manifestPolicyFromEnvironment(record);
  const catalogAuth = new AsyncLocalStorage<string>();
  const integration = createTeeProvider({
    id: "privatemode",
    name: "Privatemode",
    baseUrl: PRIVATEMODE_BASE_URL,
    apiKeyEnv: "PRIVATEMODE_API_KEY",
    policy: options.policy ?? resolvePolicy(process.env.PI_TEE_POLICY),
    assumptions: PRIVATEMODE_ASSUMPTIONS,
    catalogFetch: async (input, init) => {
      const key = catalogAuth.getStore();
      if (!key) return Response.json(SHIPPED_CATALOG);
      const response = await (options.networkFetch ?? globalThis.fetch)(
        `${PRIVATEMODE_BASE_URL}/models`,
        {
          ...init,
          redirect: "error",
          headers: { authorization: `Bearer ${key}` },
        },
      );
      if (
        response.redirected ||
        (response.url && response.url !== `${PRIVATEMODE_BASE_URL}/models`)
      )
        throw new TeeError("TEE_CATALOG_FAILED");
      return response;
    },
    parseCatalog: privatemodeCatalog,
    availableModelIds: PRIVATEMODE_MODELS,
    openSdkTransport: async () => {
      throw new TeeError("TEE_POLICY_ROUTE_REJECTED");
    },
    routes: [
      {
        id: "privatemode-mesh",
        modelIds: PRIVATEMODE_MODELS,
        potential: {
          route: "privatemode-mesh",
          provider: "Privatemode",
          cpuVerified: true,
          code: 2,
          host: 3,
          gpu: 3,
          egress: 3,
          observed: [],
        },
        openSession: async ({ apiKey, model, signal }) => {
          const admitted = await admissionPolicy.admit(signal);
          const manifest = {
            ...admitted,
            bytes: Uint8Array.from(admitted.bytes),
          };
          if (
            createHash("sha256").update(manifest.bytes).digest("hex") !==
            manifest.sha256
          )
            throw new TeeError("TEE_WORKLOAD_PIN_REJECTED");
          await record(manifest, signal);
          return openPrivatemodeTransport({
            apiKey,
            model: model.id,
            signal,
            manifest,
            networkFetch: options.networkFetch,
          });
        },
      },
    ],
  });
  const refresh = integration.provider.refreshModels!;
  integration.provider.refreshModels = (context) => {
    const key =
      context.credential?.type === "api_key"
        ? (context.credential.key ?? process.env.PRIVATEMODE_API_KEY)
        : undefined;
    return key
      ? catalogAuth.run(key, () => refresh(context))
      : refresh(context);
  };
  return integration;
}
