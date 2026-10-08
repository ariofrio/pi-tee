import { randomBytes } from "node:crypto";
import {
  createTeeProvider, resolvePolicy, withAbort,
  TeeError, type PolicyMode, type ProviderDefinition,
} from "pi-tee-core";
import { openDirectTinfoilTransport, TINFOIL_DIRECT_PROFILE } from "./direct.js";
import { openPublicWorkerTransport, PUBLIC_BUILD_PROFILE } from "./public-session.js";
import { PUBLIC_MODELS } from "./worker-appraisal.js";
import { PUBLIC_BUILD_PROFILE_ENABLED } from "./public-policy.js";
import { parseTinfoilCatalog, TINFOIL_BASE_URL } from "./catalog.js";
export { parseTinfoilCatalog, TINFOIL_BASE_URL } from "./catalog.js";

export const TINFOIL_ASSUMPTIONS = [
  "Local Pi, runtime, extensions, tools and the pinned Tinfoil SDK are trusted.",
  "The JS verifier accepts AMD Genoa SEV-SNP and tagged-release Sigstore provenance; AMD certificate revocation is not checked.",
  "Tinfoil's router and backend/hardware release authorities remain trusted; exact model-worker software is not independently approved.",
  "ATC/proxies may select an older authentic tagged release; SDK policy supplies no local rollback floor.",
  "The SDK can re-attest and resend after key rotation without independent approval before that resend.",
  "GPU channel assurance, runtime integrity, egress and credential-dependent sidecars depend on accepted router/guest code.",
];

export function createTinfoilProvider(options: {
  policy?: PolicyMode;
  route?: "auto" | "router" | "direct" | "direct-public";
  catalogFetch?: typeof globalThis.fetch;
  openSdkTransport?: ProviderDefinition["openSdkTransport"];
} = {}) {
  const route = options.route ?? process.env.PI_TINFOIL_ROUTE ?? "auto";
  if (route !== "auto" && route !== "router" && route !== "direct" && route !== "direct-public") throw new TeeError("TEE_ROUTE_INVALID");
  // direct-public runs the production appraisal under SDK policy while
  // production admission is closed, so it shares the profile's assumptions.
  const assumptions = route === "direct-public" ? [
    "SDK-policy route running the public-build appraisal below for the profile's models only.",
    ...PUBLIC_BUILD_PROFILE.assumptions,
  ] : route === "direct" ? [
    "Local Pi, runtime, extensions, tools, the pinned JS verifier and EHBP are trusted.",
    "This direct SDK-policy candidate pins one worker, artifact digest and launch measurement; it is not independently approved.",
    "The AMD Genoa JS verifier supplies no revocation checks or independent GPU appraisal; fresh v3 evidence is not yet enforced.",
    "API credentials and encrypted prompts use the exact socket presenting the attested TLS SPKI; rotation fails without a resend.",
    "Runtime integrity, GPU channel assurance and model integrity still require qualification of the pinned guest and model artifacts.",
  ] : TINFOIL_ASSUMPTIONS;
  return createTeeProvider({
    id: "tinfoil", name: "Tinfoil", baseUrl: TINFOIL_BASE_URL, apiKeyEnv: "TINFOIL_API_KEY",
    policy: options.policy ?? resolvePolicy(process.env.PI_TINFOIL_POLICY),
    parseCatalog: parseTinfoilCatalog, catalogFetch: options.catalogFetch, assumptions,
    publicBuildProfile: (route === "auto" || route === "direct-public") && PUBLIC_BUILD_PROFILE_ENABLED ? PUBLIC_BUILD_PROFILE : undefined,
    availableModelIds: route === "direct-public" ? Object.keys(PUBLIC_MODELS) : route === "direct" ? [TINFOIL_DIRECT_PROFILE.model] : undefined,
    openSdkTransport: options.openSdkTransport ?? (route === "direct-public" ? ({ signal, model }) => openPublicWorkerTransport(signal, model.id) : route === "direct" ? ({ signal }) => openDirectTinfoilTransport(signal) : async ({ signal }) => {
      const { SecureClient } = await import("tinfoil");
      signal.throwIfAborted();
      const client = new SecureClient({ baseURL: TINFOIL_BASE_URL, transport: "ehbp", userCacheSecret: randomBytes(32).toString("hex") });
      await withAbort(client.ready(), signal);
      return { fetch: client.fetch };
    }),
  });
}
