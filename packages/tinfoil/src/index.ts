import { randomBytes } from "node:crypto";
import {
  createTeeProvider, resolvePolicy, withAbort,
  type PolicyMode, type ProviderDefinition,
} from "@ariofrio/pi-tee-core";
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
  catalogFetch?: typeof globalThis.fetch;
  openSdkTransport?: ProviderDefinition["openSdkTransport"];
} = {}) {
  return createTeeProvider({
    id: "tinfoil", name: "Tinfoil", baseUrl: TINFOIL_BASE_URL, apiKeyEnv: "TINFOIL_API_KEY",
    policy: options.policy ?? resolvePolicy(process.env.PI_TINFOIL_POLICY),
    parseCatalog: parseTinfoilCatalog, catalogFetch: options.catalogFetch, assumptions: TINFOIL_ASSUMPTIONS,
    openSdkTransport: options.openSdkTransport ?? (async ({ signal }) => {
      const { SecureClient } = await import("tinfoil");
      signal.throwIfAborted();
      const client = new SecureClient({ baseURL: TINFOIL_BASE_URL, transport: "ehbp", userCacheSecret: randomBytes(32).toString("hex") });
      await withAbort(client.ready(), signal);
      return { fetch: client.fetch };
    }),
  });
}
