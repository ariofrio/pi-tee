import assert from "node:assert/strict";
import { test } from "node:test";
import type { Model } from "@earendil-works/pi-ai/compat";
import { createTeeProvider } from "../packages/core/src/provider.js";

const model: Model<"openai-completions"> = {
  id: "first", name: "First", provider: "catalog-test", api: "openai-completions",
  baseUrl: "https://catalog.example/v1", reasoning: false, input: ["text"], contextWindow: 8192, maxTokens: 1024,
  cost: { input: 1, output: 2, cacheRead: 0, cacheWrite: 0 },
};
type RefreshContext = Parameters<NonNullable<ReturnType<typeof createTeeProvider>["provider"]["refreshModels"]>>[0];

test("native refresh persists startup discovery, honors freshness, and retains the catalog on failure", async () => {
  let calls = 0;
  let fail = false;
  const integration = createTeeProvider({
    id: model.provider, name: "Catalog test", baseUrl: model.baseUrl, apiKeyEnv: "TEST_API_KEY", policy: "trust-provider-and-host",
    parseCatalog: (value) => [{ ...model, id: String((value as { id: string }).id) }],
    catalogFetch: async () => { calls++; if (fail) throw new Error("offline"); return Response.json({ id: `model-${calls}` }); },
    openSdkTransport: async () => { throw new Error("catalog discovery must not open inference"); }, assumptions: [],
  });
  let stored: RefreshContext["stored"];
  const context = (allowNetwork: boolean, force = false): RefreshContext => ({
    allowNetwork, force, stored, signal: new AbortController().signal,
    publish: async (publication) => { if (publication.persist) stored = publication.persist; publication.update?.(); return true; },
  });
  await integration.initializeCatalog();
  await integration.provider.refreshModels!(context(false));
  assert.equal(stored?.models[0]?.id, "model-1");
  await integration.provider.refreshModels!(context(true));
  assert.equal(calls, 1);
  await integration.provider.refreshModels!(context(true, true));
  assert.equal(integration.provider.getModels()[0]?.id, "model-2");
  assert.equal(stored?.models[0]?.id, "model-2");
  fail = true;
  await assert.rejects(integration.provider.refreshModels!(context(true, true)), /TEE_CATALOG_FAILED/);
  assert.equal(integration.provider.getModels()[0]?.id, "model-2");
  assert.equal(integration.getReport().catalogError, "TEE_CATALOG_FAILED");
});

test("a superseded native publication cannot change the active catalog", async () => {
  let id = "first";
  const integration = createTeeProvider({
    id: model.provider, name: "Catalog test", baseUrl: model.baseUrl, apiKeyEnv: "TEST_API_KEY", policy: "trust-provider-and-host",
    parseCatalog: () => [{ ...model, id }], catalogFetch: async () => Response.json({}),
    openSdkTransport: async () => { throw new Error("unused"); }, assumptions: [],
  });
  await integration.initializeCatalog();
  id = "superseded";
  await integration.provider.refreshModels!({
    allowNetwork: true, force: true, signal: new AbortController().signal, publish: async () => false,
  });
  assert.equal(integration.provider.getModels()[0]?.id, "first");
});

test("offline restoration fixes transport fields and public-build policy still hides the restored catalog", async () => {
  const integration = createTeeProvider({
    id: model.provider, name: "Catalog test", baseUrl: model.baseUrl, apiKeyEnv: "TEST_API_KEY",
    parseCatalog: () => [], catalogFetch: async () => { throw new Error("offline refresh must not fetch"); },
    openSdkTransport: async () => { throw new Error("unused"); }, assumptions: [],
  });
  await integration.provider.refreshModels!({
    allowNetwork: false, signal: new AbortController().signal,
    stored: { checkedAt: Date.now(), models: [{ ...model, baseUrl: "https://attacker.example", headers: { "x-secret": "bad" } }] },
    publish: async (publication) => { publication.update?.(); return true; },
  });
  assert.deepEqual(integration.provider.getModels(), []);
  integration.setPolicy("trust-provider-and-host");
  assert.equal(integration.provider.getModels()[0]?.baseUrl, model.baseUrl);
  assert.equal(integration.provider.getModels()[0]?.headers, undefined);
});
