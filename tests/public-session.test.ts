import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeContext, type Model } from "@earendil-works/pi-ai/compat";
import { createTeeProvider } from "../packages/core/src/provider.js";

const model: Model<"openai-completions"> = {
  id: "public-model", name: "Public model", provider: "public-test", api: "openai-completions",
  baseUrl: "https://catalog.invalid/v1", reasoning: false, input: ["text"], contextWindow: 8192, maxTokens: 1024,
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
};
const context = normalizeContext({ messages: [{ role: "user", content: "synthetic public session", timestamp: 1 }] });

test("public policy uses an owned admitted session rather than its SDK transport or caller endpoint", async () => {
  let sends = 0;
  let disposed = 0;
  const integration = createTeeProvider({
    id: model.provider, name: "Public test", baseUrl: model.baseUrl, apiKeyEnv: "PUBLIC_TEST_KEY",
    parseCatalog: () => [model], catalogFetch: async () => Response.json({}), assumptions: [],
    openSdkTransport: async () => { throw new Error("SDK must not be selected"); },
    publicBuildProfile: {
      id: "synthetic-contract", authorityPolicyDigest: "a".repeat(64), modelIds: [model.id], baseUrl: "https://worker.invalid/v1",
      openSession: async ({ model: selected }) => {
        assert.equal(selected.id, model.id);
        const checkedAt = Date.now();
        return {
          admission: { profile: "synthetic-contract", model: model.id, authorityPolicyDigest: "a".repeat(64), checkedAt, expiresAt: checkedAt + 60000,
            workloadDigest: "b".repeat(64), platformDigest: "c".repeat(64), cvmManifestDigest: "d".repeat(64), imageDigest: "e".repeat(64), configDigest: "f".repeat(64) },
          transport: { baseUrl: "https://worker.invalid/v1", dispose: () => { disposed++; }, fetch: async (input, init) => {
            const request = new Request(input, init); sends++;
            assert.equal(request.url, "https://worker.invalid/v1/chat/completions");
            assert.equal(request.headers.get("authorization"), "Bearer synthetic-key");
            assert.equal((await request.json()).model, model.id);
            return new Response('data: {"id":"c1","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n', { headers: { "content-type": "text/event-stream" } });
          } },
        };
      },
    },
  });
  await integration.initializeCatalog();
  assert.deepEqual(integration.provider.getModels().map(entry => entry.id), [model.id]);
  const result = await integration.provider.streamSimple({ ...model, baseUrl: "https://caller.invalid/v1" }, context, { apiKey: "synthetic-key" }).result();
  assert.equal(result.stopReason, "stop");
  assert.equal(sends, 1);
  await Promise.resolve();
  assert.equal(disposed, 1);
  assert.equal(integration.getReport().lastRequest, "public-build-accepted");
  assert.equal(integration.getReport().publicBuildVerification, "profile-established");
  assert.equal(integration.getReport().closedTrustSet, "profile-declared");
  assert.equal(integration.getReport().protectedSession, "not-established");
});

for (const [name, change] of [
  ["expired", { expiresAt: 1 }],
  ["wrong authority", { authorityPolicyDigest: "0".repeat(64) }],
  ["wrong profile", { profile: "another-profile" }],
  ["wrong model", { model: "another-model" }],
  ["missing digest", { imageDigest: "" }],
  ["overlong lifetime", { expiresAt: Number.MAX_SAFE_INTEGER }],
] as const) test(`public admission rejects ${name} before inference without SDK fallback`, async () => {
  let opened = 0, sent = 0, disposed = 0;
  const integration = createTeeProvider({
    id: model.provider, name: "Public test", baseUrl: model.baseUrl, apiKeyEnv: "PUBLIC_TEST_KEY",
    parseCatalog: () => [model], catalogFetch: async () => Response.json({}), assumptions: [],
    openSdkTransport: async () => { throw new Error("SDK fallback"); },
    publicBuildProfile: {
      id: "synthetic-contract", authorityPolicyDigest: "a".repeat(64), modelIds: [model.id], baseUrl: "https://worker.invalid/v1",
      openSession: async () => {
        opened++;
        const checkedAt = Date.now();
        return { admission: Object.assign({
          profile: "synthetic-contract", model: model.id, authorityPolicyDigest: "a".repeat(64), checkedAt, expiresAt: checkedAt + 60000,
          workloadDigest: "b".repeat(64), platformDigest: "c".repeat(64), cvmManifestDigest: "d".repeat(64), imageDigest: "e".repeat(64), configDigest: "f".repeat(64),
        }, change), transport: { baseUrl: "https://worker.invalid/v1", dispose: () => { disposed++; }, fetch: async () => { sent++; throw new Error("Unexpected send"); } } };
      },
    },
  });
  await integration.initializeCatalog();
  const result = await integration.provider.streamSimple(model, context, { apiKey: "synthetic-key", maxRetries: 20 }).result();
  assert.equal(result.errorMessage, "TEE_PUBLIC_SESSION_REJECTED");
  assert.equal(sent, 0); assert.equal(opened, 1);
  await Promise.resolve(); assert.equal(disposed, 1);
  assert.equal(integration.getReport().publicBuildVerification, "not-established");
});

test("expiry during a Pi payload hook prevents a send at the final transport boundary", async () => {
  let now = Date.now();
  const originalNow = Date.now;
  let sent = 0;
  try {
    Date.now = () => now;
    const integration = createTeeProvider({
      id: model.provider, name: "Public test", baseUrl: model.baseUrl, apiKeyEnv: "PUBLIC_TEST_KEY",
      parseCatalog: () => [model], catalogFetch: async () => Response.json({}), assumptions: [],
      openSdkTransport: async () => { throw new Error("SDK fallback"); },
      publicBuildProfile: {
        id: "synthetic-contract", authorityPolicyDigest: "a".repeat(64), modelIds: [model.id], baseUrl: "https://worker.invalid/v1",
        openSession: async () => ({ admission: {
          profile: "synthetic-contract", model: model.id, authorityPolicyDigest: "a".repeat(64), checkedAt: now, expiresAt: now + 60000,
          workloadDigest: "b".repeat(64), platformDigest: "c".repeat(64), cvmManifestDigest: "d".repeat(64), imageDigest: "e".repeat(64), configDigest: "f".repeat(64),
        }, transport: { baseUrl: "https://worker.invalid/v1", fetch: async () => { sent++; throw new Error("Unexpected send"); } } }),
      },
    });
    await integration.initializeCatalog();
    const result = await integration.provider.streamSimple(model, context, { apiKey: "synthetic-key", onPayload: () => { now += 60001; } }).result();
    assert.equal(result.errorMessage, "TEE_PUBLIC_SESSION_REJECTED");
    assert.equal(sent, 0);
  } finally { Date.now = originalNow; }
});
