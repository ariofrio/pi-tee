import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { createHash, sign, X509Certificate } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { normalizeContext, Type } from "@earendil-works/pi-ai/compat";
import type { Collateral, VerifiedReport } from "@phala/dcap-qvl";
import { createChutesProvider } from "../packages/chutes/src/index.js";
import { acceptRequest, serverStream } from "./chutes-crypto-fixture.js";

const modelId = "test/Chat-TEE";
const chute = "08901219-159f-55a7-87cf-9d0d02744668";
const instance = "d91710da-1c0e-450a-aaee-8b925783d233";
const raw = { id: modelId, chute_id: chute, confidential_compute: true, context_length: 8192, max_output_length: 1024, supported_features: ["tools", "reasoning"] };
const context = normalizeContext({ messages: [{ role: "user", content: "private-prompt-π", timestamp: 1 }] });

async function fixture(fault?: string) {
  await mkdir(".scratch/work", { recursive: true });
  const dir = await mkdtemp(resolve(".scratch/work/chutes-"));
  assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=chutes-synthetic", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { stdio: "ignore" }).status, 0);
  const cert = new X509Certificate(await readFile(join(dir, "cert.pem")));
  const signingKey = await readFile(join(dir, "key.pem"));
  const server = ml_kem768.keygen();
  const publicKey = Buffer.from(server.publicKey).toString("base64");
  const hops: Request[] = [];
  let opened: any;
  let cancelled = false;
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    hops.push(request.clone());
    const url = new URL(request.url);
    if (url.pathname === "/v1/models") return Response.json({ data: [raw] });
    if (url.pathname === `/e2e/instances/${chute}`) return Response.json({ nonce_expires_in: fault === "stale" ? 0 : 55,
      instances: [{ instance_id: instance, e2e_pubkey: publicKey, nonces: ["single-use-invocation-token"] }] });
    if (url.pathname === `/chutes/${chute}/evidence`) {
      const nonce = url.searchParams.get("nonce")!;
      const quote = Buffer.alloc(636);
      quote.writeUInt16LE(4, 0); quote.writeUInt32LE(0x81, 4);
      Buffer.from("939a7233f79c4ca9940a0db3957f0607", "hex").copy(quote, 12);
      Buffer.from(fault === "floor" ? "020102" : "030102", "hex").copy(quote, 48);
      Buffer.from("0000001000000000", "hex").copy(quote, 168);
      createHash("sha256").update((fault === "nonce" ? "00".repeat(32) : nonce) + publicKey).digest().copy(quote, 568);
      createHash("sha256").update(cert.publicKey.export({ type: "spki", format: "der" })).digest().copy(quote, 600);
      if (fault === "key") quote[568] = quote[568]! ^ 1;
      const quoted = quote.toString("base64");
      const body = Buffer.from(JSON.stringify({ nonce, evidence: { tdx_quote: quoted, nvtrust_evidence: "[]" } }));
      return Response.json({ evidence: [{ instance_id: fault === "outside" ? "unverified-recipient" : instance, tee_type: "tdx", quote: quoted,
        certificate: cert.raw.toString("base64"), signature: sign("sha256", body, signingKey).toString("base64"), attested_body: body.toString("base64"), gpu_evidence: [] }] });
    }
    assert.equal(url.href, "https://api.chutes.ai/e2e/invoke");
    assert.equal(request.headers.get("authorization"), "Bearer synthetic-key");
    assert.equal(request.headers.get("x-instance-id"), instance);
    assert.equal(request.headers.get("x-e2e-nonce"), "single-use-invocation-token");
    const blob = new Uint8Array(await request.arrayBuffer());
    for (const marker of ["private-prompt", "private-tool", "private-reasoning"]) {
      assert.equal(Buffer.from(blob).includes(Buffer.from(marker)), false);
      assert.equal([...request.headers].some(([, value]) => value.includes(marker)), false);
    }
    opened = acceptRequest(blob, server.secretKey);
    if (fault === "invoke") return new Response(null, { status: 403 });
    if (fault === "stall") {
      const response = serverStream(opened.e2e_response_pk, ['data: {"id":"c1","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":null}]}\n\n'], "truncated");
      const bytes = new TextEncoder().encode(await response.text());
      return new Response(new ReadableStream({ start(controller) { controller.enqueue(bytes); }, cancel() { cancelled = true; } }), { headers: response.headers });
    }
    return serverStream(opened.e2e_response_pk, ['data: {"id":"c1","choices":[{"index":0,"delta":{"reasoning_content":"checked","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}\n\n']);
  };
  const cpu = {
    collateral: async () => ({ tcb_info: '{"tcbEvaluationDataNumber":20}', qe_identity: '{"tcbEvaluationDataNumber":20}' }) as Collateral,
    verify: (quote: Uint8Array) => ({ status: "UpToDate", report: { asTd10: () => ({
      teeTcbSvn: quote.subarray(48, 64), tdAttributes: quote.subarray(168, 176), reportData: quote.subarray(568, 632),
    }) } }) as unknown as VerifiedReport,
  };
  return { fetch, cpu, hops, opened: () => opened, cancelled: () => cancelled, remove: () => rm(dir, { recursive: true, force: true }) };
}

test("native Chutes dispatch seals prompt, tools and reasoning before the unattested API hop", async () => {
  const f = await fixture();
  try {
    const integration = createChutesProvider({ policy: "trust-provider-and-host,host=current", catalogFetch: f.fetch, seams: { fetch: f.fetch, cpu: f.cpu } });
    await integration.initializeCatalog();
    const model = integration.provider.getModels()[0]!;
    const toolContext = normalizeContext({ messages: context.messages, tools: [{ name: "private-tool", description: "private-tool-description", parameters: Type.Object({ value: Type.String() }) }] });
    const result = await integration.provider.streamSimple(model, toolContext, { apiKey: "synthetic-key",
      onPayload: body => ({ ...(body as object), reasoning: { effort: "private-reasoning" } }),
    }).result();
    assert.equal(result.stopReason, "stop", JSON.stringify({ error: result.errorMessage, opened: !!f.opened(), posts: f.hops.filter(r => r.method === "POST").length }));
    assert.ok(f.opened().messages.some((m: any) => m.content === "private-prompt-π"));
    assert.equal(f.opened().tools[0].function.name, "private-tool");
    assert.equal(f.hops.filter(r => r.method === "POST").length, 1);
    for (const hop of f.hops.filter(r => r.method === "GET")) {
      assert.equal(hop.body, null);
      assert.ok(!hop.url.includes("private-"));
      assert.ok([...hop.headers].every(([, value]) => !value.includes("private-")));
      assert.equal(hop.headers.has("authorization"), new URL(hop.url).pathname.startsWith("/e2e/instances/"));
    }
    const levels = integration.getReport().routeDecisions![0]!.security!;
    assert.deepEqual([levels.code, levels.host, levels.gpu, levels.egress], [3, 1, 3, 3]);
    assert.ok(integration.getReport().assumptions.some(s => s.includes("X-E2E-Nonce")));
  } finally { await f.remove(); }
});

test("authenticated below-floor Chutes hosts can be admitted only by a policy allowing H2", async () => {
  const f = await fixture("floor");
  try {
    const integration = createChutesProvider({ policy: "trust-provider-and-host,host=outdated-firmware", catalogFetch: f.fetch, seams: { fetch: f.fetch, cpu: f.cpu } });
    await integration.initializeCatalog();
    const result = await integration.provider.streamSimple(integration.provider.getModels()[0]!, context, { apiKey: "synthetic-key" }).result();
    assert.equal(result.stopReason, "stop");
    assert.equal(integration.getReport().routeDecisions![0]!.security!.host, 2);
  } finally { await f.remove(); }
});

test("expiry during Pi's payload hook cannot send content under stale evidence", async () => {
  const f = await fixture();
  const originalNow = Date.now;
  const now = Date.now.bind(Date);
  try {
    const integration = createChutesProvider({ policy: "trust-provider-and-host,host=current", catalogFetch: f.fetch, seams: { fetch: f.fetch, cpu: f.cpu } });
    await integration.initializeCatalog();
    const result = await integration.provider.streamSimple(integration.provider.getModels()[0]!, context, { apiKey: "synthetic-key",
      onPayload: payload => { Date.now = () => now() + 60001; return payload; },
    }).result();
    assert.equal(result.errorMessage, "TEE_PUBLIC_SESSION_REJECTED");
    assert.equal(f.hops.some(r => r.method === "POST"), false);
  } finally { Date.now = originalNow; await f.remove(); }
});

test("a Chutes invocation rejection cannot cause a resend or plaintext fallback", async () => {
  const f = await fixture("invoke");
  try {
    const integration = createChutesProvider({ policy: "trust-provider-and-host,host=current", catalogFetch: f.fetch, seams: { fetch: f.fetch, cpu: f.cpu } });
    await integration.initializeCatalog();
    const result = await integration.provider.streamSimple(integration.provider.getModels()[0]!, context, { apiKey: "synthetic-key", maxRetries: 5 }).result();
    assert.equal(result.stopReason, "error");
    assert.equal(f.hops.filter(r => r.method === "POST").length, 1);
  } finally { await f.remove(); }
});

test("cancellation after an authenticated text delta aborts Chutes response reads", async () => {
  const f = await fixture("stall");
  const controller = new AbortController();
  try {
    const integration = createChutesProvider({ policy: "trust-provider-and-host,host=current", catalogFetch: f.fetch, seams: { fetch: f.fetch, cpu: f.cpu } });
    await integration.initializeCatalog();
    const stream = integration.provider.streamSimple(integration.provider.getModels()[0]!, context, { apiKey: "synthetic-key", signal: controller.signal });
    for await (const event of stream) if (event.type === "text_delta") controller.abort();
    assert.equal((await stream.result()).stopReason, "aborted");
    assert.equal(f.hops.filter(r => r.method === "POST").length, 1);
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(f.cancelled(), true);
  } finally { controller.abort(); await f.remove(); }
});

test("wrong nonce, swapped key, stale evidence, below-floor host and recipient outside the evidence closure never receive a prompt", async () => {
  for (const fault of ["nonce", "key", "stale", "floor", "outside"]) {
    const f = await fixture(fault);
    try {
      const integration = createChutesProvider({ policy: "trust-provider-and-host,host=current", catalogFetch: f.fetch, seams: { fetch: f.fetch, cpu: f.cpu } });
      await integration.initializeCatalog();
      const result = await integration.provider.streamSimple(integration.provider.getModels()[0]!, context, { apiKey: "synthetic-key" }).result();
      assert.equal(result.stopReason, "error", fault);
      assert.equal(f.hops.some(r => r.method === "POST"), false, fault);
      if (fault === "floor") assert.equal(integration.getReport().routeDecisions![0]!.security!.host, 2);
    } finally { await f.remove(); }
  }
});

test("provider-excluding policies reject Chutes before discovery or inference", async () => {
  const f = await fixture();
  try {
    const integration = createChutesProvider({ policy: "trust-provider", catalogFetch: f.fetch, seams: { fetch: f.fetch, cpu: f.cpu } });
    await integration.initializeCatalog();
    assert.deepEqual(integration.provider.getModels(), []);
    const result = await integration.provider.streamSimple({ id: modelId } as any, context, { apiKey: "synthetic-key" }).result();
    assert.equal(result.stopReason, "error");
    assert.ok(f.hops.every(r => new URL(r.url).pathname === "/v1/models"));
  } finally { await f.remove(); }
});
