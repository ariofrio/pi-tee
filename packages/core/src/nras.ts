import { createHash } from "node:crypto";
import { createLocalJWKSet, jwtVerify } from "jose";
import { readBoundedBody } from "./transport.js";
import { TeeError } from "./policy.js";

const ISSUER = "https://nras.attestation.nvidia.com";

/** Authenticates the detached EAT bundle. Callers must still enforce every G threshold. */
export async function runNrasVerifier(options: { evidence: { arch?: unknown; evidence?: unknown; certificate?: unknown; nonce?: unknown }[]; nonce: string; signal: AbortSignal; fetch?: typeof globalThis.fetch }): Promise<{ code: number; stdout: string }> {
  try {
    const fetch = options.fetch ?? globalThis.fetch;
    if (!/^[a-f0-9]{64}$/.test(options.nonce) || !options.evidence.length || options.evidence.length > 8) throw Error();
    const responses = await Promise.all([
      fetch(`${ISSUER}/v4/attest/gpu`, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ arch: options.evidence[0]!.arch, nonce: options.nonce, evidence_list: options.evidence, claims_version: "3.0" }), signal: options.signal, redirect: "error" }),
      fetch(`${ISSUER}/.well-known/jwks.json`, { signal: options.signal, redirect: "error" }),
    ]);
    const [bundle, keys] = await Promise.all(responses.map(async response => {
      if (!response.ok) throw Error();
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(response.body, 2 * 1024 * 1024, options.signal)));
    }));
    const jwks = createLocalJWKSet(keys);
    const authenticate = async (token: unknown) => {
      if (typeof token !== "string") throw Error();
      const { payload } = await jwtVerify(token, jwks, { algorithms: ["ES384"], issuer: ISSUER, requiredClaims: ["exp", "nbf", "iat"] });
      if (typeof payload.iat !== "number" || payload.iat > Date.now() / 1000 || payload.eat_nonce !== options.nonce) throw Error();
      return payload;
    };
    if (!Array.isArray(bundle) || bundle.length !== 2 || bundle[0]?.[0] !== "JWT") throw Error();
    const overall = await authenticate(bundle[0][1]);
    if (overall["x-nvidia-overall-att-result"] !== true) throw Error();
    const tokens = bundle[1], submods = overall.submods as Record<string, unknown>;
    if (!tokens || !submods || Object.keys(tokens).length !== options.evidence.length || Object.keys(submods).length !== options.evidence.length) throw Error();
    const claims = [];
    for (let i = 0; i < options.evidence.length; i++) {
      const name = `GPU-${i}`, token = tokens[name];
      if (typeof token !== "string" || JSON.stringify(submods[name]) !== JSON.stringify(["DIGEST", ["SHA-256", createHash("sha256").update(token).digest("hex")]])) throw Error();
      claims.push(await authenticate(token));
    }
    return { code: 0, stdout: JSON.stringify({ result_code: 0, claims }) };
  } catch {
    options.signal.throwIfAborted();
    throw new TeeError("TEE_GPU_POLICY_REJECTED");
  }
}
