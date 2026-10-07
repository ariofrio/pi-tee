import { randomBytes } from "node:crypto";
import {
  createTeeProvider, resolvePolicy, withAbort,
  TeeError, type PolicyMode, type ProviderDefinition,
} from "pi-tee-core";
import { openDirectTinfoilTransport, TINFOIL_DIRECT_PROFILE } from "./direct.js";
import { INTEL_PUBLIC_BUILD_PROFILE, openIntelTinfoilTransport } from "./intel.js";
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
  route?: "router" | "direct" | "direct-intel" | "direct-public";
  catalogFetch?: typeof globalThis.fetch;
  openSdkTransport?: ProviderDefinition["openSdkTransport"];
} = {}) {
  const route = options.route ?? process.env.PI_TINFOIL_ROUTE ?? "router";
  if (route !== "router" && route !== "direct" && route !== "direct-intel" && route !== "direct-public") throw new TeeError("TEE_ROUTE_INVALID");
  const assumptions = route === "direct-public" ? [
    "Experimental SDK-policy candidate: local Pi/runtime/extensions/tools, the hash-pinned public-build helper/dependencies, Docker image/runtime and NVIDIA verifier are trusted.",
    "Intel roots, revocation, UpToDate appraisal and local floors authenticate fresh CPU-bound device and endpoint keys; named public Tinfoil workload/guest/platform/freshness workflows authorize dynamic releases.",
    "GitHub Actions OIDC/hosted builds and the finite Sigstore roots are trusted; the named release publisher endorses OCI build/source claims, without an independent builder signature or rebuild.",
    "Public source, authenticated guest/kernel/initrd/OCI artifacts, RTMR1/RTMR2 and the constrained Gemma runtime configuration are bound to the CPU-accepted signed predicate before GPU appraisal or inference; full running key/channel/reset qualification and implementation review remain incomplete.",
    "Exactly one CPU-bound Hopper report must pass local NVIDIA signed references, revocation, nonce, secure-boot/debug and authenticated SPT checks; driver/VBIOS use explicit minimum versions rather than deployment pins.",
    "TLS SPKI authenticates the inference socket before credentials/EHBP ciphertext; send once, reject rotation and encrypt a fresh cache salt. Tinfoil retains availability and credential/billing authority.",
  ] : route === "direct-intel" ? [
    "Local Pi/runtime/extensions/tools, the hash-pinned Go CPU verifier and its dependencies, Docker runtime/image, and hash-pinned NVIDIA local verifier are trusted.",
    "Fresh Intel TDX quote authentication, revocation and UpToDate status enforce locally frozen guest registers and CPU security policy; no current provider release/reference authorizes a workload.",
    "The exact CPU-bound GPU evidence is appraised locally against NVIDIA roots, driver/VBIOS pins, signed references and OCSP, then required to declare authenticated SPT mode; compute-channel and reset lifecycle still require full runtime qualification.",
    "This is a candidate, not independent software approval: frozen boot registers were initially acquired from provider material; guest, engine, weights and key custody still need independent review.",
    "Attested TLS SPKI authenticates the exact inference socket before credentials or EHBP ciphertext; send once, fail on rotation, and generate a fresh encrypted vLLM cache salt.",
    "Tinfoil retains availability and credential/billing authority; local clock and manufacturer endorsement/reference/revocation processes are trusted.",
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
    publicBuildProfile: route === "direct-public" && PUBLIC_BUILD_PROFILE_ENABLED ? INTEL_PUBLIC_BUILD_PROFILE : undefined,
    availableModelIds: route !== "router" ? [TINFOIL_DIRECT_PROFILE.model] : undefined,
    openSdkTransport: options.openSdkTransport ?? (route === "direct-public" ? ({ signal }) => openIntelTinfoilTransport(signal, "public-builds") : route === "direct-intel" ? ({ signal }) => openIntelTinfoilTransport(signal) : route === "direct" ? ({ signal }) => openDirectTinfoilTransport(signal) : async ({ signal }) => {
      const { SecureClient } = await import("tinfoil");
      signal.throwIfAborted();
      const client = new SecureClient({ baseURL: TINFOIL_BASE_URL, transport: "ehbp", userCacheSecret: randomBytes(32).toString("hex") });
      await withAbort(client.ready(), signal);
      return { fetch: client.fetch };
    }),
  });
}
