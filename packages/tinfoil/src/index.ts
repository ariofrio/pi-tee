import { randomBytes } from "node:crypto";
import {
  createTeeProvider, resolvePolicy, withAbort,
  TeeError, type PolicyMode, type ProviderDefinition,
} from "pi-tee-core";
import { openRatedPublicWorkerTransport } from "./public-session.js";
import { PUBLIC_MODELS } from "./worker-appraisal.js";
import { PUBLIC_BUILD_PROFILE_ENABLED } from "./public-policy.js";
import { parseTinfoilCatalog, TINFOIL_BASE_URL } from "./catalog.js";
export { parseTinfoilCatalog, TINFOIL_BASE_URL } from "./catalog.js";

export const TINFOIL_ASSUMPTIONS = [
  "Local OS, clock, Pi/runtime, enabled extensions/hooks/tools, locked dependencies and hash-checked verifier modules are trusted.",
  "Intel, AMD and NVIDIA are trusted as manufacturers. Evidence and route-wide levels are established for each request, including hidden plaintext components.",
  "Admitted public publishers are trusted for release correctness; B3 uses GitHub hosted workflows and Sigstore, without independent reproduction or per-release review.",
  "Direct transport binds keys before credentials/body and sends once. Router transport follows SDK rotation/retry behavior within its provider-and-host trust position.",
  "API credentials and authorization metadata reach Tinfoil. Whole-Pi-session protection remains unestablished.",
];

export function createTinfoilProvider(options: {
  policy?: PolicyMode;
  route?: "auto" | "router" | "direct" | "direct-public";
  catalogFetch?: typeof globalThis.fetch;
  openSdkTransport?: ProviderDefinition["openSdkTransport"];
} = {}) {
  for (const variable of ["PI_TINFOIL_POLICY", "PI_TINFOIL_ROUTE"]) {
    if (process.env[variable] !== undefined) throw new TeeError("TEE_POLICY_INVALID", `${variable} was removed; use PI_TEE_POLICY. Routes are selected by verified levels.`);
  }
  const route = options.route ?? "auto";
  if (!["auto", "router", "direct", "direct-public"].includes(route)) throw new TeeError("TEE_ROUTE_INVALID");
  const publicPotential = { route: "tinfoil-direct", provider: "Tinfoil", cpuVerified: true, code: 1 as const, host: 1 as const, gpu: 1 as const, egress: 2 as const, build: 3 as const, review: 3 as const, observed: [] };
  const routerSecurity = { route: "tinfoil-router", provider: "Tinfoil", cpuVerified: true, code: 3 as const, host: 3 as const, gpu: 3 as const, egress: 3 as const,
    observed: ["Router and hidden worker/sidecar code is not fully pinned by client checks.", "CPU evidence has no client nonce; AMD revocation and local firmware floors are unchecked.", "Worker GPU protection is unchecked; web-search and sidecar paths can carry plaintext.", "Router tags are signed, but their build workflow and runner are unchecked (B4 for the router component).", "Tinfoil handling commitments have not been reviewed.", "SDK re-attests and resends once only on EHBP key-configuration mismatch; other request failures are not retried."] };
  return createTeeProvider({
    id: "tinfoil", name: "Tinfoil", baseUrl: TINFOIL_BASE_URL, apiKeyEnv: "TINFOIL_API_KEY",
    policy: options.policy ?? resolvePolicy(process.env.PI_TEE_POLICY),
    parseCatalog: parseTinfoilCatalog, catalogFetch: options.catalogFetch,
    assumptions: [...TINFOIL_ASSUMPTIONS, "Intel OutOfDate TDX direct workers are unavailable under every policy; the pinned verifier rejects them during authentication."],
    openSdkTransport: async () => { throw new TeeError("TEE_POLICY_ROUTE_REJECTED"); },
    routes: [
      ...(route === "router" || !PUBLIC_BUILD_PROFILE_ENABLED ? [] : [{ id: "tinfoil-direct", potential: publicPotential, limitations: ["Intel OutOfDate TDX workers are skipped under every policy because the pinned verifier rejects them during authentication."], modelIds: Object.keys(PUBLIC_MODELS),
        openSession: async ({ signal, model, policy }: { signal: AbortSignal; model: { id: string }; policy: import("pi-tee-core").SecurityPolicy }) => openRatedPublicWorkerTransport(signal, model.id, policy),
      }]),
      ...(route === "direct" || route === "direct-public" ? [] : [{ id: "tinfoil-router", potential: routerSecurity,
        openSession: async ({ apiKey, signal, model }: { apiKey: string; signal: AbortSignal; model: import("pi-tee-core").TeeCatalogModel }) => {
          const transport = options.openSdkTransport ? await options.openSdkTransport({ apiKey, signal, model }) : await (async () => {
            const { SecureClient } = await import("tinfoil");
            signal.throwIfAborted();
            const client = new SecureClient({ baseURL: TINFOIL_BASE_URL, transport: "ehbp", userCacheSecret: randomBytes(32).toString("hex") });
            await withAbort(client.ready(), signal);
            return { fetch: client.fetch };
          })();
          const security = options.openSdkTransport ? (transport as import("pi-tee-core").SdkTransport & { security?: import("pi-tee-core").RouteSecurity }).security : routerSecurity;
          if (!security) { (transport as import("pi-tee-core").SdkTransport).dispose?.(); throw new TeeError("TEE_ATTESTATION_REJECTED"); }
          return { security, transport };
        },
      }]),
    ],
    availableModelIds: route === "direct" || route === "direct-public" ? Object.keys(PUBLIC_MODELS) : undefined,
  });
}
