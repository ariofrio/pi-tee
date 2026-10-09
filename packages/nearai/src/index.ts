import {
  authenticateResponse, createTeeProvider, limitResponseBody, MAX_ENCRYPTED_RESPONSE_BYTES, resolveModelVisibility, resolvePolicy, TeeError, withAbort,
  type GpuPolicyTable, type ModelVisibility, type PolicyMode, type ProviderDefinition,
} from "pi-tee-core";
import { NEAR_BASE_URL } from "./catalog.js";
import { openNearGatewayTransport } from "./gateway.js";
import { loadNearCatalog } from "./discovery.js";
import { openDirectNearTransport, NEAR_DIRECT_PROFILE } from "./direct.js";
export { NEAR_BASE_URL, parseNearCatalog } from "./catalog.js";

export const NEAR_ASSUMPTIONS = [
  "Local Pi, runtime, extensions, tools and the pinned NEAR SDK are trusted.",
  "Intel signatures, revocation and fresh nonce/key binding are required; H1 additionally requires local TDX SVN and collateral-edition floors. GPU coverage is unknown (G3); optional details are appraised locally, never through NRAS.",
  "NEAR gateway/model release, key-service, shared-key recipient and runtime deployment authorities remain trusted under provider-trust positions.",
  "Gateway TLS binding, OHTTP and model field encryption follow the SDK protocol; serving-instance identity is not established.",
  "A model-signed response is required before any completion or tool call is exposed; its shared signer does not identify one approved serving instance.",
  "Model assets, runtime downloads, mutation controls and deployment provenance have no independent approval in this position.",
  "Commitments (shown, not gated): NEAR's ToS/DPA do not promise contractual no-retention; they retain data for the time period needed.",
  "Commitments (deployed behavior unverified): inspected prod-tagged Responses code stores transcripts without a TTL; inspected Chat Completions code does not persist transcript content.",
  "Commitments (shown, not gated): NEAR promises no training on your data and lists ISO 27001; no public SOC 2 report was found (an engagement letter is listed).",
  "Commitments (shown, not gated): the sub-processor list does not consistently cover Chutes-backed models, which introduce another processor.",
];

// The SDK gateway route relies on node:https socket pinning; the direct route owns its node:tls socket.
export function assertNearRuntime(route: "gateway" | "direct") {
  if ((route === "gateway" && process.versions.bun) || Number(process.versions.node.split(".")[0]) < 24) throw new TeeError("TEE_RUNTIME_UNSUPPORTED");
}

export function createNearProvider(options: {
  policy?: PolicyMode;
  route?: "gateway" | "direct";
  modelVisibility?: ModelVisibility;
  catalogFetch?: typeof globalThis.fetch;
  openSdkTransport?: ProviderDefinition["openSdkTransport"];
} = {}) {
  for (const variable of ["PI_NEARAI_POLICY", "PI_NEARAI_ROUTE"]) {
    if (process.env[variable] !== undefined) throw new TeeError("TEE_POLICY_INVALID", `${variable} was removed; use PI_TEE_POLICY. Routes are selected by verified levels.`);
  }
  const route = options.route;
  if (route && route !== "gateway" && route !== "direct") throw new TeeError("TEE_ROUTE_INVALID");
  const policy = options.policy ?? resolvePolicy(process.env.PI_TEE_POLICY);
  const potential = { provider: "NEAR", cpuVerified: true, code: 3 as const, host: 1 as const, gpu: 3 as const, egress: 3 as const, observed: [] };
  return createTeeProvider({
    id: "nearai", name: "NEAR AI", baseUrl: NEAR_BASE_URL, apiKeyEnv: "NEARAI_API_KEY", policy,
    modelVisibility: options.modelVisibility ?? resolveModelVisibility(process.env.PI_NEARAI_MODEL_VISIBILITY),
    parseCatalog: loadNearCatalog, requireDeclaredTee: true, catalogFetch: options.catalogFetch, assumptions: NEAR_ASSUMPTIONS,
    openSdkTransport: options.openSdkTransport ?? (async () => { throw new TeeError("TEE_POLICY_ROUTE_REJECTED"); }),
    routes: [
      ...(route === "gateway" ? [] : [{ id: "near-direct", potential: { ...potential, route: "near-direct" }, modelIds: [NEAR_DIRECT_PROFILE.model],
        openSession: async ({ apiKey, signal }: { apiKey: string; signal: AbortSignal }) => {
          assertNearRuntime("direct");
          const transport = await openDirectNearTransport(apiKey, signal);
          return { security: transport.security, transport };
        },
      }]),
      ...(route === "direct" ? [] : [{ id: "near-gateway", potential: { ...potential, route: "near-gateway" },
        openSession: async ({ apiKey, signal, model }: { apiKey: string; signal: AbortSignal; model: { id: string } }) => {
          const transport = options.openSdkTransport ? { ...await options.openSdkTransport({ apiKey, signal, model: model as import("pi-tee-core").TeeCatalogModel }), security: { ...potential, route: "near-gateway", observed: [] } } : await openNearGatewayTransport(apiKey, signal, model.id);
          return { security: transport.security, transport };
        },
      }]),
    ],
    availableModelIds: route === "direct" ? [NEAR_DIRECT_PROFILE.model] : undefined,
  });
}
