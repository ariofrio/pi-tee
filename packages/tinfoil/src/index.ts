import {
  createTeeProvider, resolvePolicy,
  TeeError, type PolicyMode,
} from "pi-tee-core";
import { openRatedPublicWorkerTransport } from "./public-session.js";
import { GATEWAY_LIMITATIONS, GATEWAY_MODELS, openRatedGatewayTransport } from "./gateway.js";
import { PUBLIC_MODELS } from "./worker-appraisal.js";
import { PUBLIC_BUILD_PROFILE_ENABLED } from "./public-policy.js";
import { openRatedRouterTransport, ROUTER_POTENTIAL, type RouterSeams } from "./router.js";
import { parseTinfoilCatalog, TINFOIL_BASE_URL } from "./catalog.js";
export { parseTinfoilCatalog, TINFOIL_BASE_URL } from "./catalog.js";

export const TINFOIL_ASSUMPTIONS = [
  "Local OS, clock, Pi/runtime, enabled extensions/hooks/tools, locked dependencies and hash-checked verifier modules are trusted.",
  "Intel, AMD and NVIDIA are trusted as manufacturers. Evidence and route-wide levels are established for each request, including hidden plaintext components.",
  "Admitted public publishers are trusted for release correctness; B3 uses GitHub hosted workflows and Sigstore, without independent reproduction or per-release review.",
  "Direct transport binds keys before credentials/body and sends once. Gateway uses WebPKI TLS to an unattested billing host that receives the API key, model and headers; bodies are sealed to the appraised worker. A 412 is terminal, with no resend. Router transport also binds the freshly appraised router's keys and sends once; the router can read plaintext and selects unappraised workers.",
  "API credentials and authorization metadata reach Tinfoil. Whole-Pi-session protection remains unestablished.",
];

export function createTinfoilProvider(options: {
  policy?: PolicyMode;
  route?: "auto" | "router" | "direct" | "direct-public" | "gateway";
  catalogFetch?: typeof globalThis.fetch;
  /** Test seams for the router's evidence, verifier and wire. */
  router?: RouterSeams;
} = {}) {
  for (const variable of ["PI_TINFOIL_POLICY", "PI_TINFOIL_ROUTE"]) {
    if (process.env[variable] !== undefined) throw new TeeError("TEE_POLICY_INVALID", `${variable} was removed; use PI_TEE_POLICY. Routes are selected by verified levels.`);
  }
  const route = options.route ?? "auto";
  if (!["auto", "router", "direct", "direct-public", "gateway"].includes(route)) throw new TeeError("TEE_ROUTE_INVALID");
  const publicPotential = { route: "tinfoil-direct", provider: "Tinfoil", cpuVerified: true, code: 1 as const, host: 1 as const, gpu: 1 as const, egress: 2 as const, build: 3 as const, review: 3 as const, observed: [] };
  return createTeeProvider({
    id: "tinfoil", name: "Tinfoil", baseUrl: TINFOIL_BASE_URL, apiKeyEnv: "TINFOIL_API_KEY",
    policy: options.policy ?? resolvePolicy(process.env.PI_TEE_POLICY),
    parseCatalog: parseTinfoilCatalog, catalogFetch: options.catalogFetch,
    assumptions: [...TINFOIL_ASSUMPTIONS, ...(PUBLIC_BUILD_PROFILE_ENABLED && (route === "auto" || route === "gateway") ? GATEWAY_LIMITATIONS : []), "Intel OutOfDate TDX direct workers are unavailable under every policy; the pinned verifier rejects them during authentication."],
    openSdkTransport: async () => { throw new TeeError("TEE_POLICY_ROUTE_REJECTED"); },
    routes: [
      ...(route === "router" || route === "gateway" || !PUBLIC_BUILD_PROFILE_ENABLED ? [] : [{ id: "tinfoil-direct", potential: publicPotential, limitations: ["Intel OutOfDate TDX workers are skipped under every policy because the pinned verifier rejects them during authentication."], modelIds: Object.keys(PUBLIC_MODELS),
        openSession: async ({ signal, model, policy }: { signal: AbortSignal; model: { id: string }; policy: import("pi-tee-core").SecurityPolicy }) => openRatedPublicWorkerTransport(signal, model.id, policy),
      }]),
      ...(route !== "auto" && route !== "gateway" || !PUBLIC_BUILD_PROFILE_ENABLED ? [] : [{ id: "tinfoil-gateway", potential: { ...publicPotential, route: "tinfoil-gateway" }, modelIds: GATEWAY_MODELS,
        ...(route === "auto" ? { fallbackFor: "tinfoil-direct", preferenceReason: "Direct exposes the API key and metadata to fewer parties." } : {}),
        openSession: async ({ signal, model, policy }: { signal: AbortSignal; model: { id: string }; policy: import("pi-tee-core").SecurityPolicy }) => openRatedGatewayTransport(signal, model.id, policy),
      }]),
      ...(route === "direct" || route === "direct-public" || route === "gateway" ? [] : [{ id: "tinfoil-router", potential: ROUTER_POTENTIAL,
        openSession: async ({ signal, policy }: { signal: AbortSignal; policy: import("pi-tee-core").SecurityPolicy }) => openRatedRouterTransport(signal, policy, options.router),
      }]),
    ],
    availableModelIds: route === "gateway" ? GATEWAY_MODELS : route === "direct" || route === "direct-public" ? Object.keys(PUBLIC_MODELS) : undefined,
  });
}
