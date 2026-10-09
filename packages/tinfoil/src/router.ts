import { randomBytes } from "node:crypto";
import { parsePolicy, readBoundedBody, TeeError, type RouteSecurity, type SdkTransport, type SecurityPolicy } from "pi-tee-core";
import { TINFOIL_BASE_URL } from "./catalog.js";
import { openEncryptedWorkerTransport } from "./direct.js";
import { verifyPublicBuildArtifacts } from "./public-build.js";

/** The router behind `TINFOIL_BASE_URL`; its TLS key is the one its attestation report binds. */
export const ROUTER_HOST = "inference.tinfoil.sh";
export const ROUTER_REPO = "tinfoilsh/confidential-model-router";

const ROUTER_LIMITATIONS = [
  "Hidden worker and sidecar code is not pinned by client checks; their CPU evidence never reaches the client, so the route stays H3.",
  "Worker GPU protection is unchecked; web-search and sidecar paths can carry plaintext.",
  "Tinfoil handling commitments have not been reviewed.",
  "Sends once over TLS pinned to the attested router key; a key rotation or any other failure ends the dispatch without a resend.",
];

export const ROUTER_POTENTIAL: RouteSecurity = Object.freeze({
  route: "tinfoil-router", provider: "Tinfoil", cpuVerified: true, code: 3, host: 3, gpu: 3, egress: 3,
  observed: ["The router's own release and CPU are appraised under a fresh nonce before each dispatch.", ...ROUTER_LIMITATIONS],
});

export type RouterSeams = { evidenceFetch?: typeof globalThis.fetch; verifyArtifacts?: typeof verifyPublicBuildArtifacts; wireFetch?: typeof globalThis.fetch };

function requireCondition(ok: unknown, code: string): asserts ok { if (!ok) throw new TeeError(code); }

/**
 * Fresh appraisal of the router: CPU report, AMD/Intel collateral and
 * revocation, local firmware floors, platform and its tagged public release.
 * Returns the quote-bound endpoint keys only after all of it passes.
 */
export async function appraiseRouter(options: { signal: AbortSignal; policy?: SecurityPolicy } & Omit<RouterSeams, "wireFetch">) {
  const challengeAt = Date.now();
  const signal = AbortSignal.any([options.signal, AbortSignal.timeout(120000)]);
  signal.throwIfAborted();
  const nonce = randomBytes(32).toString("hex");
  const response = await (options.evidenceFetch ?? globalThis.fetch)(`https://${ROUTER_HOST}/.well-known/tinfoil-attestation?nonce=${nonce}`, { signal, redirect: "error" });
  if (!response.ok) await response.body?.cancel();
  requireCondition(response.ok, "TEE_ATTESTATION_REJECTED");
  const raw = new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(response.body, 2 * 1024 * 1024, signal));
  const envelope = JSON.parse(raw);
  const policy = options.policy ?? parsePolicy();
  const build = await (options.verifyArtifacts ?? verifyPublicBuildArtifacts)({
    raw, nonce, signal, repo: ROUTER_REPO, evidenceFetch: options.evidenceFetch, allowOutdated: policy.host !== "current", role: "router",
  });
  requireCondition(build.repo === ROUTER_REPO && (build.platform === "tdx" || build.platform === "sev-snp"), "TEE_PUBLIC_BUILD_REJECTED");
  requireCondition(build.hostLevel === 1 || (build.hostLevel === 2 && policy.host !== "current"), "TEE_CPU_POLICY_REJECTED");
  signal.throwIfAborted();
  const keys = JSON.parse(Buffer.from(envelope.crypto_material, "base64").toString("utf8")).items;
  const tls = keys.find((k: { id: string; format: string }) => k.id === "tls" && k.format === "https://tinfoil.sh/key/spki-fp-sha256/v1");
  const hpke = keys.find((k: { id: string; format: string }) => k.id === "hpke" && k.format === "https://tinfoil.sh/key/x25519-hpke/v1");
  requireCondition(/^[a-f0-9]{64}$/.test(tls?.data ?? "") && /^[a-f0-9]{64}$/.test(hpke?.data ?? ""), "TEE_ATTESTATION_REJECTED");
  const checkedAt = Date.now();
  const expiresAt = Math.min(checkedAt + 60000, challengeAt + 300000,
    Date.parse(build.codeFreshness) + 7 * 86400000, Date.parse(build.platformFreshness) + 7 * 86400000);
  requireCondition(Number.isSafeInteger(expiresAt) && expiresAt > checkedAt, "TEE_PUBLIC_SESSION_REJECTED");
  const security: RouteSecurity = { ...ROUTER_POTENTIAL, observed: [
    `${ROUTER_HOST}: ${ROUTER_REPO} ${build.tag} on ${build.platform}, appraised under a fresh nonce with the manufacturer's revocation list and pi-tee's firmware floors. Its release is checked against the public tagged workflow on GitHub-hosted runners.`,
    ...(build.hostLevel === 2 ? ["Router firmware is below local floors; authenticated publisher minima and production restrictions still passed."] : []),
    ...ROUTER_LIMITATIONS,
  ] };
  return { tls: tls.data as string, hpke: hpke.data as string, expiresAt, security };
}

export async function openRatedRouterTransport(signal: AbortSignal, policy: SecurityPolicy, seams: RouterSeams = {}): Promise<{ security: RouteSecurity; transport: SdkTransport }> {
  const { wireFetch, ...appraisal } = seams;
  const router = await appraiseRouter({ signal, policy, ...appraisal });
  return { security: router.security, transport: await openEncryptedWorkerTransport(signal, ROUTER_HOST, router, router.expiresAt, TINFOIL_BASE_URL, wireFetch) };
}
