import {
  assessRoute, compareRoutes, RouteFailure, RouteRejection, createTeeProvider, describeUpstream, resolveModelVisibility, resolvePolicy, TeeError, upstreamFailure,
  type ModelVisibility, type UpstreamCause, type PolicyMode, type ProviderDefinition, type RouteSecurity, type SecurityPolicy,
} from "pi-tee-core";
import { NEAR_BASE_URL } from "./catalog.js";
import { openNearGatewayTransport, type NearGatewaySeams } from "./gateway.js";
import { discoverNearDirectEndpoints, loadNearCatalog } from "./discovery.js";
import { openDirectNearTransport, type NearDirectTarget } from "./direct.js";
export { NEAR_BASE_URL, parseNearCatalog } from "./catalog.js";

export const NEAR_ASSUMPTIONS = [
  "Local Pi, runtime, extensions, tools and the pinned NEAR SDK are trusted.",
  "Intel signatures, revocation and fresh nonce/key binding are required; H1 additionally requires local TDX SVN and collateral-edition floors. GPU coverage is unknown (G3); optional details are appraised locally, never through NRAS.",
  "NEAR gateway/model release, key-service, shared-key recipient and runtime deployment authorities remain trusted under provider-trust positions.",
  "Gateway OHTTP and model field encryption follow the SDK protocol on one owned connection to the quote-bound TLS key; gateway replicas share that key, so serving-instance identity is not established.",
  "A model-signed response is required before any completion or tool call is exposed; its shared signer does not identify one approved serving instance.",
  "Model assets, runtime downloads, mutation controls and deployment provenance have no independent approval in this position.",
  "Commitments (shown, not gated): NEAR's ToS/DPA do not promise contractual no-retention; they retain data for the time period needed.",
  "Commitments (deployed behavior unverified): inspected prod-tagged Responses code stores transcripts without a TTL; inspected Chat Completions code does not persist transcript content.",
  "Commitments (shown, not gated): NEAR promises no training on your data and lists ISO 27001; no public SOC 2 report was found (an engagement letter is listed).",
  "Commitments (shown, not gated): the sub-processor list does not consistently cover Chutes-backed models, which introduce another processor.",
];

// Both routes own one node:tls socket, which Node 24+ and Bun provide.
export function assertNearRuntime() {
  if (Number(process.versions.node.split(".")[0]) < 24) throw new TeeError("TEE_RUNTIME_UNSUPPORTED");
}

/** The SDK's structured failure keeps only the status; its message is never read. */
function nearUpstream(error: unknown): UpstreamCause | undefined {
  const seen = new Set<unknown>();
  while (error && typeof error === "object" && !seen.has(error)) {
    seen.add(error);
    if (error instanceof TeeError && error.upstream) return error.upstream;
    if (error instanceof TeeError && error.code === "TEE_CONNECTION_FAILED") return upstreamFailure(error.code).upstream;
    const { failure } = error as { failure?: { code?: unknown; details?: { status?: unknown } } };
    if (failure?.code === "api.transport_failed") return upstreamFailure("TEE_ATTESTATION_REJECTED").upstream;
    if (failure?.code === "api.http_status" && Number.isSafeInteger(failure.details?.status)) return upstreamFailure("TEE_ATTESTATION_REJECTED", failure.details!.status as number, "evidence").upstream;
    error = (error as { cause?: unknown }).cause;
  }
  return undefined;
}

function directFailureReason(error: unknown, timedOut: boolean): string {
  const seen = new Set<unknown>();
  let transportFailed = false;
  let evidenceCode: string | undefined;
  while (error && typeof error === "object" && !seen.has(error)) {
    seen.add(error);
    if (error instanceof TeeError) {
      if (error.code === "TEE_TLS_KEY_REJECTED") return "TLS/WebPKI rejected (TEE_TLS_KEY_REJECTED)";
      if (error.code === "TEE_CONNECTION_FAILED") return "unreachable (TEE_CONNECTION_FAILED)";
      if (/^TEE_[A-Z_]+$/.test(error.code)) evidenceCode = error.code;
    }
    const wrapped = error as { failure?: { code?: string }; cause?: unknown };
    if (wrapped.failure?.code === "api.transport_failed") transportFailed = true;
    error = wrapped.cause;
  }
  if (evidenceCode) return `evidence rejected (${evidenceCode})`;
  return timedOut || transportFailed ? "unreachable (transport unavailable)" : "evidence rejected";
}

export function createNearProvider(options: {
  policy?: PolicyMode;
  route?: "gateway" | "direct";
  modelVisibility?: ModelVisibility;
  catalogFetch?: typeof globalThis.fetch;
  directSeams?: (target: NearDirectTarget) => Parameters<typeof openDirectNearTransport>[3];
  gatewaySeams?: NearGatewaySeams;
  openSdkTransport?: ProviderDefinition["openSdkTransport"];
} = {}) {
  for (const variable of ["PI_NEARAI_POLICY", "PI_NEARAI_ROUTE"]) {
    if (process.env[variable] !== undefined) throw new TeeError("TEE_POLICY_INVALID", `${variable} was removed; use PI_TEE_POLICY. Routes are selected by verified levels.`);
  }
  const route = options.route;
  if (route && route !== "gateway" && route !== "direct") throw new TeeError("TEE_ROUTE_INVALID");
  const policy = options.policy ?? resolvePolicy(process.env.PI_TEE_POLICY);
  const potential = { provider: "NEAR", cpuVerified: true, code: 3 as const, host: 1 as const, gpu: 3 as const, egress: 3 as const, observed: [] };
  const directModelIds: string[] = [];
  let directEndpoints = new Map<string, string[]>();
  let discoveryNotes: string[] = [];
  const integration = createTeeProvider({
    id: "nearai", name: "NEAR AI", baseUrl: NEAR_BASE_URL, apiKeyEnv: "NEARAI_API_KEY", policy,
    modelVisibility: options.modelVisibility ?? resolveModelVisibility(process.env.PI_NEARAI_MODEL_VISIBILITY),
    parseCatalog: async (value, context) => {
      const models = await loadNearCatalog(value, context);
      if (route === "gateway") return models;
      try {
        directEndpoints = await discoverNearDirectEndpoints(models, context);
        discoveryNotes = [`Direct discovery: ${directEndpoints.size} catalog/registry candidates; levels are unestablished until per-request appraisal.`];
      } catch {
        directEndpoints = new Map();
        discoveryNotes = ["Direct discovery unavailable or incomplete; no direct candidates offered. Gateway eligibility is unchanged."];
      }
      directModelIds.splice(0, directModelIds.length, ...directEndpoints.keys());
      return models;
    }, requireDeclaredTee: true, catalogFetch: options.catalogFetch, assumptions: NEAR_ASSUMPTIONS,
    openSdkTransport: options.openSdkTransport ?? (async () => { throw new TeeError("TEE_POLICY_ROUTE_REJECTED"); }),
    routes: [
      ...(route === "gateway" ? [] : [{ id: "near-direct", potential: { ...potential, route: "near-direct" }, modelIds: directModelIds, available: () => true,
        openSession: async ({ apiKey, signal, model, policy }: { apiKey: string; signal: AbortSignal; model: { id: string }; policy: SecurityPolicy }) => {
          assertNearRuntime();
          const directNotes: string[] = [];
          let upstream: UpstreamCause | undefined;
          let picked: Awaited<ReturnType<typeof openDirectNearTransport>> | undefined;
          let rejected: RouteSecurity | undefined;
          try {
            for (const hostname of directEndpoints.get(model.id) ?? []) {
              const target = { model: model.id, hostname };
              const bounded = AbortSignal.any([signal, AbortSignal.timeout(120_000)]);
              let transport: Awaited<ReturnType<typeof openDirectNearTransport>>;
              try { transport = await openDirectNearTransport(apiKey, bounded, target, options.directSeams?.(target)); }
              catch (error) {
                signal.throwIfAborted();
                const cause = nearUpstream(error);
                upstream ??= cause;
                directNotes.push(`${hostname}: skipped (${directFailureReason(error, bounded.aborted)}${cause ? `; upstream: ${describeUpstream(cause)}` : ""}); no levels established.`);
                continue;
              }
              const assessed = assessRoute(policy, transport.security);
              if (!assessed.accepted) {
                if (!rejected || compareRoutes(transport.security, rejected) < 0) rejected = transport.security;
                directNotes.push(`${hostname}: skipped by policy (${assessed.reason}).`);
                transport.dispose?.();
              } else if (!picked || compareRoutes(transport.security, picked.security) < 0) {
                picked?.dispose?.();
                picked = transport;
              } else transport.dispose?.();
            }
            signal.throwIfAborted();
            if (!picked) {
              if (rejected) throw new RouteRejection(rejected, directNotes);
              throw new RouteFailure("near-direct", "TEE_ATTESTATION_REJECTED", directNotes, upstream);
            }
            return { security: picked.security, transport: picked, notes: directNotes };
          } catch (error) { picked?.dispose?.(); throw error; }
        },
      }]),
      ...(route === "direct" ? [] : [{ id: "near-gateway", potential: { ...potential, route: "near-gateway" },
        openSession: async ({ apiKey, signal, model }: { apiKey: string; signal: AbortSignal; model: { id: string } }) => {
          assertNearRuntime();
          const transport = options.openSdkTransport ? await options.openSdkTransport({ apiKey, signal, model: model as import("pi-tee-core").TeeCatalogModel }) as import("pi-tee-core").SdkTransport & { security?: import("pi-tee-core").RouteSecurity } : await openNearGatewayTransport(apiKey, signal, model.id, options.gatewaySeams).catch((error: unknown) => {
            const cause = nearUpstream(error);
            if (!cause || signal.aborted || error instanceof RouteRejection || (error instanceof TeeError && error.upstream)) throw error;
            throw new TeeError(error instanceof TeeError ? error.code : "TEE_ATTESTATION_REJECTED", undefined, cause);
          });
          if (!transport.security) { transport.dispose?.(); throw new TeeError("TEE_ATTESTATION_REJECTED"); }
          return { security: transport.security, transport };
        },
      }]),
    ],
  });
  return { ...integration, getReport: () => {
    const report = integration.getReport();
    report.assumptions = [...report.assumptions, ...discoveryNotes];
    return report;
  } };
}
