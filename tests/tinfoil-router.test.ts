import assert from "node:assert/strict";
import { test } from "node:test";
import { Identity } from "ehbp";
import { CipherSuite, KDF_HKDF_SHA256, AEAD_AES_256_GCM } from "hpke";
import { KEM_DHKEM_X25519_HKDF_SHA256 } from "@panva/hpke-noble";
import { normalizeContext } from "@earendil-works/pi-ai/compat";
import { parsePolicy, formatProviderReport } from "../packages/core/src/index.js";
import { createTinfoilProvider } from "../packages/tinfoil/src/index.js";
import { appraiseRouter, openRatedRouterTransport, ROUTER_REPO, type RouterSeams } from "../packages/tinfoil/src/router.js";
import { verifyPublicBuildArtifacts } from "../packages/tinfoil/src/public-build.js";

const tls = "c6".repeat(32);
const policy = parsePolicy("trust-provider-and-host");

async function open(router: Identity, request: Request) {
  const enc = Buffer.from(request.headers.get("ehbp-encapsulated-key")!, "hex");
  const recipient = await new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM)
    .SetupRecipient(router.getPrivateKey(), enc, { info: new TextEncoder().encode("ehbp request") });
  return JSON.parse(new TextDecoder().decode(await recipient.Open(new Uint8Array(await request.arrayBuffer()).subarray(4))));
}

// Serves a synthetic envelope under each fresh nonce; the verifier seam stands in
// for the bundled helper and records what the route asked it to authenticate.
async function seams(overrides: { repo?: string; hostLevel?: number } = {}) {
  const router = await Identity.generate();
  const nonces: string[] = [];
  const verified: Parameters<typeof verifyPublicBuildArtifacts>[0][] = [];
  const crypto = Buffer.from(JSON.stringify({ items: [
    { id: "tls", format: "https://tinfoil.sh/key/spki-fp-sha256/v1", data: tls },
    { id: "hpke", format: "https://tinfoil.sh/key/x25519-hpke/v1", data: await router.getPublicKeyHex() },
  ] })).toString("base64");
  const deps: RouterSeams = {
    evidenceFetch: async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      assert.equal(`${url.origin}${url.pathname}`, "https://inference.tinfoil.sh/.well-known/tinfoil-attestation");
      assert.equal(request.headers.get("authorization"), null, "Evidence requests carry no credentials.");
      nonces.push(url.searchParams.get("nonce")!);
      return Response.json({ challenge: { nonce: nonces.at(-1) }, crypto_material: crypto, device_evidence: "", collateral: [] });
    },
    verifyArtifacts: (async (options: Parameters<typeof verifyPublicBuildArtifacts>[0]) => {
      verified.push(options);
      const now = new Date().toISOString();
      return { repo: overrides.repo ?? ROUTER_REPO, platform: "sev-snp", hostLevel: overrides.hostLevel ?? 2, tag: "v0.0.155", codeFreshness: now, platformFreshness: now };
    }) as unknown as typeof verifyPublicBuildArtifacts,
  };
  return { router, nonces, verified, deps };
}

test("router appraisal uses a fresh nonce per dispatch and admits only the router release", async () => {
  const { nonces, verified, deps } = await seams();
  const first = await appraiseRouter({ signal: AbortSignal.timeout(10000), policy, ...deps });
  await appraiseRouter({ signal: AbortSignal.timeout(10000), policy, ...deps });
  assert.equal(nonces.length, 2);
  assert.notEqual(nonces[0], nonces[1]);
  assert.ok(nonces.every(nonce => /^[a-f0-9]{64}$/.test(nonce)));
  assert.deepEqual(verified.map(v => [v.nonce, v.repo, v.role, v.allowOutdated]), nonces.map(nonce => [nonce, ROUTER_REPO, "router", true]));
  assert.equal(first.tls, tls);
  assert.ok(first.expiresAt > Date.now() && first.expiresAt <= Date.now() + 60000);

  for (const [overrides, chosen] of [[{ repo: "tinfoilsh/confidential-gemma4-31b" }, policy], [{ hostLevel: 3 }, policy], [{ hostLevel: 2 }, parsePolicy("trust-provider-and-host,host=current")]] as const) {
    const rejected = await seams(overrides);
    await assert.rejects(appraiseRouter({ signal: AbortSignal.timeout(10000), policy: chosen, ...rejected.deps }), /TEE_/);
  }
});

test("router dispatch is sealed to the attested key and never resent", async () => {
  const { router, deps } = await seams();
  let sends = 0;
  const { security, transport } = await openRatedRouterTransport(AbortSignal.timeout(10000), policy, { ...deps, wireFetch: async (input, init) => {
    sends++;
    const request = new Request(input, init);
    assert.equal(request.url, "https://inference.tinfoil.sh/v1/chat/completions");
    assert.equal(Buffer.from(await request.clone().arrayBuffer()).includes(Buffer.from("synthetic router prompt")), false);
    const body = await open(router, request);
    assert.equal(body.messages[0].content, "synthetic router prompt");
    assert.match(body.cache_salt, /^[a-f0-9]{64}$/);
    // A key rotation surfaces as an error status; it must not trigger re-attestation or a resend.
    return new Response("rotated", { status: 422 });
  } });
  assert.deepEqual([security.route, security.code, security.host, security.gpu, security.egress], ["tinfoil-router", 3, 3, 3, 3]);
  assert.match(security.observed.join("\n"), /fresh nonce/);
  assert.doesNotMatch(security.observed.join("\n"), /no client nonce|resends once/);
  const request = () => transport.fetch(`${transport.baseUrl}/chat/completions`, {
    method: "POST", headers: { authorization: "Bearer synthetic-key" },
    body: JSON.stringify({ model: "gpt-oss-120b", messages: [{ role: "user", content: "synthetic router prompt" }] }),
  });
  await assert.rejects(request(), /TEE_RESPONSE_REJECTED/);
  await assert.rejects(request(), /TEE_REQUEST_REJECTED/);
  assert.equal(sends, 1);
});

test("the router route sends once through the provider without the Tinfoil SDK", async () => {
  const { router, nonces, deps } = await seams();
  const attempts: string[] = [];
  const integration = createTinfoilProvider({ policy: "trust-provider-and-host", route: "router", router: { ...deps, wireFetch: async (input, init) => {
    const request = new Request(input, init);
    attempts.push(request.headers.get("authorization") ?? "");
    assert.equal((await open(router, request)).messages.at(-1).content, "synthetic rotation prompt");
    return new Response("rotated", { status: 422 });
  } },
    catalogFetch: async () => Response.json({ data: [{ id: "gpt-oss-120b", name: "Synthetic router", type: "chat", tool_calling: true, endpoints: ["/v1/chat/completions"], context_window: 8192, max_tokens: 1024, pricing: { inputTokenPricePer1M: 1, outputTokenPricePer1M: 1 } }] }),
  });
  await integration.initializeCatalog();
  const model = integration.provider.getModels()[0]!;
  const result = await integration.provider.streamSimple(model, normalizeContext({ messages: [{ role: "user", content: "synthetic rotation prompt", timestamp: 1 }] }), { apiKey: "synthetic-key", maxRetries: 10 }).result();
  assert.equal(result.stopReason, "error");
  assert.deepEqual(attempts, ["Bearer synthetic-key"]);
  assert.equal(nonces.length, 1);
  assert.match(formatProviderReport(integration.getReport()), /without a resend/);
});
