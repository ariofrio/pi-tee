import { createTeeProvider, resolvePolicy, TeeError, type PolicyMode } from "pi-tee-core";
import { CHUTES_BASE_URL, parseChutesCatalog } from "./catalog.js";
import { openChutesTransport, type ChutesSeams } from "./transport.js";
export { CHUTES_BASE_URL, parseChutesCatalog } from "./catalog.js";

export const CHUTES_ASSUMPTIONS = [
  "Local Pi, runtime, extensions, tools and the locked DCAP/ML-KEM dependencies are trusted; Intel's signatures and revocation are checked locally using Intel PCS collateral.",
  "Chutes controls serving software (A3); it may change code, read bodies, send them elsewhere or store them (X3). No verified runtime or key-custody closure establishes A1 or A2.",
  "H1 needs a fresh per-request nonce, authenticated ML-KEM key and host TLS SPKI, UpToDate status and pi-tee's TDX SVN and collateral floors; below-floor fresh evidence is H2. Unverified or stale evidence is never dispatched.",
  "GPU serving coverage is unknown (G3). Host trust is required even with H1; GPU reports cannot establish closure under A3. No NRAS calls are made.",
  "Ordinary hostname-verified WebPKI HTTPS at api.chutes.ai sees Authorization (API key), X-Chute-Id, X-Instance-Id, X-E2E-Nonce (single-use invocation token), X-E2E-Stream, X-E2E-Path, Content-Type, Host, Content-Length, Connection: close, request sizes, timing and client IP. Discovery exposes the chute ID; evidence lookup exposes the client nonce. llm.chutes.ai sees public model-catalog requests without credentials.",
  "Prompt, tool definitions/results, reasoning and the response public key are inside the encrypted JSON body to the freshly attested instance ML-KEM key. Response content is authenticated encrypted SSE; usage counters outside that encryption are Chutes billing metadata. Chutes and the selected instance see decrypted bodies; the public API TLS key is not attested.",
  "The provider-controlled runtime may forward plaintext or hold keys outside the verified instance; those limits are unverified under A3/G3/X3, not promises of a closed serving implementation. Provider catalog labels and commitments never raise a level.",
  "Invocation owns a hostname-verified WebPKI TLS 1.3 socket and sends one encrypted request, including after HTTP 421; no resend, plaintext fallback or rotated-key recovery. A new Pi request requires new evidence and a new invocation token. Independent approval and whole-session protection are not established.",
];

export function createChutesProvider(options: { policy?: PolicyMode; catalogFetch?: typeof globalThis.fetch; seams?: ChutesSeams } = {}) {
  const policy = options.policy ?? resolvePolicy(process.env.PI_TEE_POLICY);
  return createTeeProvider({
    id: "chutes", name: "Chutes", baseUrl: CHUTES_BASE_URL, apiKeyEnv: "CHUTES_API_KEY", policy,
    parseCatalog: parseChutesCatalog, catalogFetch: options.catalogFetch, requireDeclaredTee: true, assumptions: CHUTES_ASSUMPTIONS,
    openSdkTransport: async () => { throw new TeeError("TEE_POLICY_ROUTE_REJECTED"); },
    routes: [{ id: "chutes-e2ee", potential: { route: "chutes-e2ee", provider: "Chutes", cpuVerified: true,
      code: 3, host: 1, gpu: 3, egress: 3, observed: [] },
      openSession: async ({ apiKey, signal, model, policy }) => {
        const transport = await openChutesTransport(apiKey, model.id, signal, policy, options.seams);
        return { security: transport.security, transport };
      },
    }],
  });
}
