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

test("public profiles declare their own trust assumptions and canonical configuration", () => {
  const profile = {
    id: "contract", authorityPolicyDigest: "a".repeat(64), modelIds: [model.id],
    baseUrl: "https://worker.invalid/v1", assumptions: ["Public publisher"],
    openSession: async () => { throw new Error("Must not open"); },
  };
  const definition = {
    id: model.provider, name: "Public test", baseUrl: model.baseUrl, apiKeyEnv: "PUBLIC_TEST_KEY",
    parseCatalog: () => [model], assumptions: ["SDK authority"],
    openSdkTransport: async () => { throw new Error("SDK fallback"); },
  };
  for (const change of [
    { assumptions: [] }, { assumptions: [""] }, { id: "" }, { modelIds: [] },
    { modelIds: [""] }, { authorityPolicyDigest: "bad" }, { baseUrl: "http://worker.invalid/v1" },
    { baseUrl: "https://worker.invalid/v1?override" },
  ]) assert.throws(() => createTeeProvider({ ...definition, publicBuildProfile: { ...profile, ...change } }), /TEE_PUBLIC_PROFILE_INVALID/);
  assert.throws(() => createTeeProvider({ ...definition, publicBuildProfiles: [profile, { ...profile, modelIds: ["other"] }] }), /TEE_PUBLIC_PROFILE_INVALID/);
});

test("overlapping public workload profiles reject before catalog or session work", () => {
  let calls = 0;
  const makeProfile = (id: string) => ({
    id, authorityPolicyDigest: "a".repeat(64), modelIds: [model.id], baseUrl: `https://${id}.invalid/v1`, assumptions: ["Public publisher"],
    openSession: async () => { calls++; throw new Error("Must not open"); },
  });
  assert.throws(() => createTeeProvider({
    id: model.provider, name: "Public test", baseUrl: model.baseUrl, apiKeyEnv: "PUBLIC_TEST_KEY",
    parseCatalog: () => [model], catalogFetch: async () => { calls++; return Response.json({}); }, assumptions: [],
    openSdkTransport: async () => { calls++; throw new Error("SDK fallback"); },
    publicBuildProfiles: [makeProfile("first"), makeProfile("second")],
  }), /TEE_PUBLIC_PROFILE_INVALID/);
  assert.equal(calls, 0);
});

test("public policy binds each catalog model to its own profile, authority and endpoint", async () => {
  const second = { ...model, id: "second-public-model", name: "Second public model" };
  const sends: string[] = [];
  let endpointReads = 0;
  const profiles = [model, second].map((entry, index) => ({
    id: `contract-${index}`, authorityPolicyDigest: String(index + 1).repeat(64), modelIds: [entry.id],
    baseUrl: `https://worker-${index}.invalid/v1`, assumptions: [`Publisher ${index}`],
    openSession: async ({ model: selected }: { model: Model<"openai-completions"> }) => {
      assert.equal(selected.id, entry.id);
      const checkedAt = Date.now();
      return {
        admission: { profile: `contract-${index}`, model: selected.id, authorityPolicyDigest: String(index + 1).repeat(64),
          checkedAt, expiresAt: checkedAt + 60000, workloadDigest: "b".repeat(64), platformDigest: "c".repeat(64),
          cvmManifestDigest: "d".repeat(64), imageDigest: "e".repeat(64), configDigest: "f".repeat(64) },
        transport: { get baseUrl() { endpointReads++; return `https://worker-${index}.invalid/v1`; }, fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
          const request = new Request(input, init);
          assert.equal(request.url, `https://worker-${index}.invalid/v1/chat/completions`);
          assert.equal((await request.json()).model, entry.id);
          sends.push(entry.id);
          return new Response('data: {"id":"c1","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n', { headers: { "content-type": "text/event-stream" } });
        } },
      };
    },
  }));
  const integration = createTeeProvider({
    id: model.provider, name: "Public test", baseUrl: model.baseUrl, apiKeyEnv: "PUBLIC_TEST_KEY",
    parseCatalog: () => [model, second], catalogFetch: async () => Response.json({}), assumptions: [],
    openSdkTransport: async () => { throw new Error("SDK fallback"); }, publicBuildProfiles: profiles,
  });
  await integration.initializeCatalog();
  assert.deepEqual(integration.provider.getModels().map(entry => entry.id), [model.id, second.id]);
  assert.deepEqual(integration.getReport().assumptions, ["[contract-0] Publisher 0", "[contract-1] Publisher 1"]);
  for (const entry of [model, second]) {
    const result = await integration.provider.streamSimple({ ...entry, baseUrl: "https://caller.invalid/v1" }, context, { apiKey: "synthetic-key" }).result();
    assert.equal(result.stopReason, "stop");
    assert.equal(integration.getReport().lastAdmission?.model, entry.id);
  }
  assert.deepEqual(sends, [model.id, second.id]);
  assert.equal(endpointReads, 2, "Each admitted endpoint is captured once before validation and dispatch.");
});

test("a public session cannot borrow another workload profile's endpoint", async () => {
  const second = { ...model, id: "second-public-model" };
  let sends = 0;
  const integration = createTeeProvider({
    id: model.provider, name: "Public test", baseUrl: model.baseUrl, apiKeyEnv: "PUBLIC_TEST_KEY",
    parseCatalog: () => [model, second], catalogFetch: async () => Response.json({}), assumptions: [],
    openSdkTransport: async () => { throw new Error("SDK fallback"); },
    publicBuildProfiles: [{
      id: "first-contract", authorityPolicyDigest: "a".repeat(64), modelIds: [model.id], baseUrl: "https://first.invalid/v1", assumptions: ["Public publisher"],
      openSession: async () => {
        const checkedAt = Date.now();
        return { admission: {
          profile: "first-contract", model: model.id, authorityPolicyDigest: "a".repeat(64), checkedAt, expiresAt: checkedAt + 60000,
          workloadDigest: "b".repeat(64), platformDigest: "c".repeat(64), cvmManifestDigest: "d".repeat(64), imageDigest: "e".repeat(64), configDigest: "f".repeat(64),
        }, transport: { baseUrl: "https://second.invalid/v1", fetch: async () => { sends++; throw new Error("Unexpected send"); } } };
      },
    }, {
      id: "second-contract", authorityPolicyDigest: "b".repeat(64), modelIds: [second.id], baseUrl: "https://second.invalid/v1", assumptions: ["Other publisher"],
      openSession: async () => { throw new Error("Wrong profile selected"); },
    }],
  });
  await integration.initializeCatalog();
  const result = await integration.provider.streamSimple(model, context, { apiKey: "synthetic-key", maxRetries: 20 }).result();
  assert.equal(result.errorMessage, "TEE_PUBLIC_SESSION_REJECTED");
  assert.equal(sends, 0);
  assert.equal(integration.getReport().publicBuildVerification, "not-established");
});

test("public policy uses an owned admitted session rather than its SDK transport or caller endpoint", async () => {
  let sends = 0;
  let disposed = 0;
  const integration = createTeeProvider({
    id: model.provider, name: "Public test", baseUrl: model.baseUrl, apiKeyEnv: "PUBLIC_TEST_KEY",
    parseCatalog: () => [{ ...model, sdkTransportAvailable: false }], catalogFetch: async () => Response.json({}), assumptions: [],
    openSdkTransport: async () => { throw new Error("SDK must not be selected"); },
    publicBuildProfile: {
      id: "synthetic-contract", authorityPolicyDigest: "a".repeat(64), modelIds: [model.id], baseUrl: "https://worker.invalid/v1", assumptions: ["Declared public publishers"],
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
  assert.deepEqual(integration.getReport().assumptions, ["Declared public publishers"]);
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
      id: "synthetic-contract", authorityPolicyDigest: "a".repeat(64), modelIds: [model.id], baseUrl: "https://worker.invalid/v1", assumptions: ["Public publisher"],
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
        id: "synthetic-contract", authorityPolicyDigest: "a".repeat(64), modelIds: [model.id], baseUrl: "https://worker.invalid/v1", assumptions: ["Public publisher"],
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
