import assert from "node:assert/strict";
import { test } from "node:test";
import { createTeeProvider } from "../packages/core/src/provider.js";
import { normalizeContext, type Model } from "@earendil-works/pi-ai/compat";
const model: Model<"openai-completions"> = {
  id: "test-model", name: "Test model", provider: "test-tee", api: "openai-completions",
  baseUrl: "https://tee.example/v1", reasoning: false, input: ["text"],
  contextWindow: 8192, maxTokens: 1024, cost: { input: 1, output: 2, cacheRead: 0, cacheWrite: 0 },
  compat: { supportsStore: false, sendSessionAffinityHeaders: false },
};
const context = normalizeContext({ messages: [{ role: "user", content: "synthetic prompt", timestamp: 1 }] });

test("only transport-owned routing can select a direct worker, after canonical model preflight", async () => {
  let received: Request | undefined;
  const integration = createTeeProvider({
    id: model.provider, name: "Test TEE", baseUrl: model.baseUrl, apiKeyEnv: "TEST_API_KEY", policy: "sdk",
    parseCatalog: () => [model], catalogFetch: async () => Response.json({ data: [] }), assumptions: [],
    openSdkTransport: async ({ model: selected }) => {
      assert.equal(selected.id, model.id);
      assert.equal(selected.baseUrl, model.baseUrl);
      return { baseUrl: "https://worker.example/v1", fetch: async (input, init) => {
        received = new Request(input, init);
        return new Response('data: {"id":"c1","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n', { headers: { "content-type": "text/event-stream" } });
      } };
    },
  });
  await integration.initializeCatalog();
  const result = await integration.provider.streamSimple({ ...model, baseUrl: "https://attacker.example" }, context, { apiKey: "test-key" }).result();
  assert.equal(result.stopReason, "stop");
  assert.equal(received?.url, "https://worker.example/v1/chat/completions");
  assert.equal(received?.headers.get("authorization"), "Bearer test-key");
});

test("a direct route hides other catalog models and rejects stale selections before attestation", async () => {
  let opened = 0;
  const integration = createTeeProvider({
    id: model.provider, name: "Test TEE", baseUrl: model.baseUrl, apiKeyEnv: "TEST_API_KEY", policy: "sdk",
    parseCatalog: () => [model, { ...model, id: "unsupported-worker" }], availableModelIds: [model.id],
    catalogFetch: async () => Response.json({ data: [] }), assumptions: [],
    openSdkTransport: async () => { opened++; throw Error("must not open"); },
  });
  await integration.initializeCatalog();
  assert.deepEqual(integration.provider.getModels().map(m => m.id), [model.id]);
  const result = await integration.provider.streamSimple({ ...model, id: "unsupported-worker" }, context, { apiKey: "test-key" }).result();
  assert.equal(result.errorMessage, "TEE_MODEL_UNAVAILABLE");
  assert.equal(opened, 0);
});

test("a per-request transport releases its resources after success, rejection or abort", async () => {
  for (const outcome of ["success", "reject", "abort"] as const) {
    const controller = new AbortController();
    let closed = 0;
    const integration = createTeeProvider({
      id: model.provider, name: "Test TEE", baseUrl: model.baseUrl, apiKeyEnv: "TEST_API_KEY", policy: "sdk",
      parseCatalog: () => [model], catalogFetch: async () => Response.json({}), assumptions: [],
      openSdkTransport: async () => ({ dispose: () => { closed++; }, fetch: async () => {
        if (outcome === "abort") { controller.abort(); throw controller.signal.reason; }
        if (outcome === "reject") return Response.json({ error: { message: "synthetic rejection" } }, { status: 401 });
        return new Response('data: {"id":"c1","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n', { headers: { "content-type": "text/event-stream" } });
      } }),
    });
    await integration.initializeCatalog();
    const result = await integration.provider.streamSimple(model, context, { apiKey: "test-key", signal: controller.signal }).result();
    assert.equal(result.stopReason, outcome === "success" ? "stop" : outcome === "abort" ? "aborted" : "error");
    assert.equal(closed, 1, "The owned transport must release resources exactly once.");
  }
});
