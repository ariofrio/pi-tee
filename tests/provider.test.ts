import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeContext, Type, type Model } from "@earendil-works/pi-ai/compat";
import { createTeeProvider } from "../packages/core/src/provider.js";
import { isRetryableAssistantError } from "@earendil-works/pi-ai/utils/retry";
import { authenticateResponse } from "../packages/core/src/response.js";

const model: Model<"openai-completions"> = {
  id: "test-model", name: "Test model", provider: "test-tee", api: "openai-completions",
  baseUrl: "https://tee.example/v1", reasoning: false, input: ["text"],
  contextWindow: 8192, maxTokens: 1024,
  cost: { input: 1, output: 2, cacheRead: 0, cacheWrite: 0 },
  compat: { supportsStore: false, sendSessionAffinityHeaders: false },
};
const context = normalizeContext({
  messages: [{ role: "user", content: "private prompt", timestamp: 1 }],
});

async function sdkProvider(fetch: typeof globalThis.fetch) {
  const integration = createTeeProvider({
    id: model.provider, name: "Test TEE", baseUrl: model.baseUrl, apiKeyEnv: "TEST_API_KEY", policy: "sdk",
    parseCatalog: () => [model], catalogFetch: async () => Response.json({ data: [] }),
    openSdkTransport: async () => ({ fetch }), assumptions: [],
  });
  await integration.initializeCatalog();
  return integration;
}

test("hosted tools added by a payload hook are rejected before reaching the transport", async () => {
  let sends = 0;
  const integration = await sdkProvider(async () => { sends++; throw new Error("external transport"); });
  const result = await integration.provider.streamSimple(model, context, {
    apiKey: "test-key", onPayload: (body) => ({ ...(body as object), tools: [{ type: "web_search" }] }),
  }).result();
  assert.equal(sends, 0);
  assert.equal(result.errorMessage, "TEE_REQUEST_REJECTED");
});

test("an ambiguous transport failure cannot be replayed by either Pi retry classifier", async () => {
  let sends = 0;
  const integration = await sdkProvider(async () => { sends++; throw new Error("Connection error: secret-token timeout"); });
  const result = await integration.provider.streamSimple(model, context, { apiKey: "test-key", maxRetries: 10 }).result();
  assert.equal(sends, 1);
  assert.equal(result.errorMessage, "TEE_REQUEST_FAILED");
  assert.equal(isRetryableAssistantError(result), false);
});

test("SDK preflight diagnostics cannot impersonate a retryable terminal security code", async () => {
  const integration = createTeeProvider({
    id: model.provider, name: "Test TEE", baseUrl: model.baseUrl, apiKeyEnv: "TEST_API_KEY", policy: "sdk",
    parseCatalog: () => [model], catalogFetch: async () => Response.json({ data: [] }),
    openSdkTransport: async () => { throw new Error("TEE_TIMEOUT"); }, assumptions: [],
  });
  await integration.initializeCatalog();
  const result = await integration.provider.streamSimple(model, context, { apiKey: "test-key" }).result();
  assert.equal(result.errorMessage, "TEE_REQUEST_FAILED");
  assert.equal(isRetryableAssistantError(result), false);
});

test("URL, header and fetch overrides cannot escape the registered transport", async () => {
  let received: Request | undefined;
  const integration = await sdkProvider(async (input, init) => {
    received = new Request(input, init);
    return new Response('data: {"id":"c1","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n', { headers: { "content-type": "text/event-stream" } });
  });
  const result = await integration.provider.streamSimple({ ...model, baseUrl: "https://attacker.example", headers: { "x-prompt": "private" } }, context, {
    apiKey: "test-key", headers: { authorization: "Bearer attacker", "x-prompt": "private" },
    fetch: async () => { throw new Error("caller fetch must not run"); },
  }).result();
  assert.equal(result.stopReason, "stop");
  assert.equal(received?.url, "https://tee.example/v1/chat/completions");
  assert.equal(received?.headers.get("authorization"), "Bearer test-key");
  assert.equal(received?.headers.get("x-prompt"), null);
  assert.equal(integration.getReport().closedTrustSet, "not-established");
});

test("SDK-policy key rotation can reconstruct the same guarded body without consuming it", async () => {
  const attempts: { url: string; authorization: string | null; body: string }[] = [];
  const integration = await sdkProvider(async (input, init) => {
    // An external SDK may reconstruct its request after attesting a rotated key.
    for (let attempt = 0; attempt < 2; attempt++) {
      const request = new Request(input, init);
      attempts.push({ url: request.url, authorization: request.headers.get("authorization"), body: await request.text() });
    }
    return new Response('data: {"id":"c1","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n', { headers: { "content-type": "text/event-stream" } });
  });
  const result = await integration.provider.streamSimple(model, context, { apiKey: "test-key" }).result();
  assert.equal(result.stopReason, "stop");
  assert.deepEqual(attempts[1], attempts[0]);
  assert.equal(attempts[1]?.url, "https://tee.example/v1/chat/completions");
  assert.equal(attempts[1]?.authorization, "Bearer test-key");
  assert.equal(JSON.parse(attempts[1]!.body).messages.at(-1).content, "private prompt");
});

test("changing to approved policy aborts an in-flight SDK request and hides SDK models", async () => {
  let started!: () => void;
  const ready = new Promise<void>((resolve) => { started = resolve; });
  const integration = await sdkProvider(async (input, init) => {
    const request = new Request(input, init);
    started();
    return new Promise<Response>((_resolve, reject) => request.signal.addEventListener("abort", () => reject(request.signal.reason), { once: true }));
  });
  const completion = integration.provider.streamSimple(model, context, { apiKey: "test-key" }).result();
  await ready;
  integration.setPolicy("approved");
  assert.equal((await completion).stopReason, "aborted");
  assert.equal(integration.provider.getModels().length, 0);
});

test("cancellation during attestation setup ends as an aborted request", async () => {
  const abort = new AbortController();
  let started!: () => void;
  const ready = new Promise<void>((resolve) => { started = resolve; });
  const integration = createTeeProvider({
    id: model.provider, name: "Test TEE", baseUrl: model.baseUrl, apiKeyEnv: "TEST_API_KEY", policy: "sdk",
    parseCatalog: () => [model], catalogFetch: async () => Response.json({ data: [] }), assumptions: [],
    openSdkTransport: ({ signal }) => {
      started();
      return new Promise((_resolve, reject) => signal.addEventListener("abort", () => reject(signal.reason), { once: true }));
    },
  });
  await integration.initializeCatalog();
  const completion = integration.provider.streamSimple(model, context, { apiKey: "test-key", signal: abort.signal }).result();
  await ready;
  abort.abort();
  assert.equal((await completion).stopReason, "aborted");
});

test("a verified tool response preserves Pi's tool arguments and usage", async () => {
  const chunk = { id: "tool-1", choices: [{ index: 0, delta: {
    tool_calls: [{ index: 0, id: "call-1", type: "function", function: { name: "echo", arguments: '{"text":"héllo 🌍"}' } }],
  }, finish_reason: "tool_calls" }], usage: { prompt_tokens: 12, completion_tokens: 7, total_tokens: 19 } };
  const body = `data: ${JSON.stringify(chunk)}\n\ndata: [DONE]\n\n`;
  const integration = await sdkProvider(async (input, init) => {
    const request = new Request(input, init);
    const payload = await request.json() as { tools: { function: { name: string } }[] };
    assert.equal(payload.tools[0]?.function.name, "echo");
    return authenticateResponse(new Response(body, { headers: { "content-type": "text/event-stream" } }), {
      signal: request.signal, verify: async (id) => { assert.equal(id, "tool-1"); },
    });
  });
  const transcript = normalizeContext({
    messages: [{ role: "user", content: "Call echo", timestamp: 1 }],
    tools: [{ name: "echo", description: "Echo text", parameters: Type.Object({ text: Type.String() }) }],
  });
  const result = await integration.provider.streamSimple(model, transcript, { apiKey: "test-key" }).result();
  assert.equal(result.stopReason, "toolUse");
  assert.deepEqual(result.content[0], { type: "toolCall", id: "call-1", name: "echo", arguments: { text: "héllo 🌍" } });
  assert.equal(result.usage.input, 12);
  assert.equal(result.usage.output, 7);
});

test("a forged tool response exposes no executable tool event to Pi", async () => {
  const body = 'data: {"id":"tool-1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"bash","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}\n\ndata: [DONE]\n\n';
  const integration = await sdkProvider(async (input, init) => authenticateResponse(new Response(body, { headers: { "content-type": "text/event-stream" } }), {
    signal: new Request(input, init).signal, verify: async () => { throw new Error("forged"); },
  }));
  const stream = integration.provider.streamSimple(model, context, { apiKey: "test-key" });
  for await (const event of stream) assert.ok(!event.type.startsWith("toolcall"));
  assert.equal((await stream.result()).stopReason, "error");
});

test("default policy blocks before the SDK or inference endpoint receives a prompt", async () => {
  let opened = false;
  const integration = createTeeProvider({
    id: model.provider, name: "Test TEE", baseUrl: model.baseUrl, apiKeyEnv: "TEST_API_KEY",
    parseCatalog: () => [model],
    openSdkTransport: async () => {
      opened = true;
      throw new Error("must never be reached");
    },
    assumptions: ["test SDK acceptance"],
  });
  const result = await integration.provider.streamSimple(model, context, { apiKey: "test-key" }).result();
  assert.equal(result.errorMessage, "TEE_APPROVED_DEPLOYMENT_UNAVAILABLE");
  assert.equal(opened, false);
});

export { model, context };

test("a payload hook cannot change the attested model identity before encryption", async () => {
  let promptSends = 0;
  const integration = createTeeProvider({
    id: model.provider, name: "Test TEE", baseUrl: model.baseUrl, apiKeyEnv: "TEST_API_KEY", policy: "sdk",
    parseCatalog: () => [model],
    catalogFetch: async () => Response.json({ data: [] }),
    openSdkTransport: async () => ({ fetch: async () => {
      promptSends++;
      throw new Error("transport endpoint reached");
    } }),
    assumptions: [],
  });
  await integration.initializeCatalog();
  const result = await integration.provider.streamSimple(model, context, {
    apiKey: "test-key", onPayload: (body) => ({ ...(body as object), model: "unapproved-model" }),
  }).result();
  assert.equal(promptSends, 0);
  assert.equal(result.errorMessage, "TEE_REQUEST_REJECTED");
});
