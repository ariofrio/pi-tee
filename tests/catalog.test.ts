import assert from "node:assert/strict";
import { test } from "node:test";
import { parseNearCatalog } from "../packages/nearai/src/catalog.js";
import { parseTinfoilCatalog } from "../packages/tinfoil/src/catalog.js";

test("NEAR catalog maps million-token costs and excludes embeddings and hosted tools", () => {
  const models = parseNearCatalog({ data: [
    { id: "near/model", name: "Model", context_length: 131072, max_output_length: 8192,
      supported_features: ["tools", "reasoning"], input_modalities: ["text", "image"],
      pricing: { input: 0.2, output: 0.6, input_cache_read: "0.00000005" } },
    { id: "embedding", supported_features: [], output_modalities: ["embedding"] },
  ] });
  assert.equal(models.length, 1);
  assert.ok(Math.abs((models[0]?.cost.cacheRead ?? NaN) - 0.05) < 1e-12);
  assert.deepEqual(models[0]?.input, ["text", "image"]);
  assert.equal(models[0]?.baseUrl, "https://cloud-api.near.ai/v1");
  // NEAR's advertised max_output_length is not enforced; Pi clamps max_tokens to remaining context.
  assert.equal(models[0]?.maxTokens, 131072);
  assert.equal(models[0]?.contextWindow, 131072);
});

test("NEAR thinking is an on/off chat-template switch only for reasoning models", () => {
  const enabled = { $var: "thinking.enabled" };
  const [reasoning, plain] = parseNearCatalog({ data: [
    { id: "near/reasoning", context_length: 8192, supported_features: ["tools", "reasoning"], supported_sampling_parameters: ["reasoning_effort"] },
    { id: "near/plain", context_length: 8192, supported_features: ["tools"] },
  ] });
  assert.equal(reasoning?.compat?.thinkingFormat, "chat-template");
  assert.deepEqual(reasoning?.compat?.chatTemplateKwargs, { thinking: enabled, enable_thinking: enabled });
  assert.equal(reasoning?.compat?.supportsReasoningEffort, false);
  assert.equal(plain?.compat?.thinkingFormat, undefined);
});

test("Tinfoil maps provider-declared thinking controls without accepting transport overrides", () => {
  const [model] = parseTinfoilCatalog({ data: [{
    id: "glm-test", type: "chat", tool_calling: true, endpoints: ["/v1/chat/completions"],
    context_window: 1048576, reasoning: true, multimodal: false,
    pricing: { inputTokenPricePer1M: 1.8, outputTokenPricePer1M: 5.75 },
    baseUrl: "https://attacker.example", headers: { "x-secret": "bad" },
    reasoning_params: { effort_map: { high: "max" }, params: { "/v1/chat/completions": { enable: { chat_template_kwargs: { reasoning_effort: "$EFFORT", transport_url: "https://attacker.example" } } } } },
  }] });
  assert.equal(model?.baseUrl, "https://inference.tinfoil.sh/v1");
  assert.equal(model?.headers, undefined);
  assert.deepEqual(model?.compat?.chatTemplateKwargs?.reasoning_effort, { $var: "thinking.effort" });
  assert.equal(Object.hasOwn(model?.compat?.chatTemplateKwargs ?? {}, "transport_url"), false);
  assert.equal(model?.thinkingLevelMap?.high, "max");
});

test("Tinfoil chat-template reasoning models always carry an on/off switch", () => {
  const enabled = { $var: "thinking.enabled" };
  const chat = (enable: unknown, disable?: unknown) => ({ params: { "/v1/chat/completions": { enable, ...(disable ? { disable } : {}) } } });
  const models = parseTinfoilCatalog({ data: [
    ["effort-only", chat({ chat_template_kwargs: { reasoning_effort: "$EFFORT" } })],
    ["declared-thinking", chat({ chat_template_kwargs: { reasoning_effort: "$EFFORT", thinking: true } }, { chat_template_kwargs: { thinking: false } })],
    ["declared-enable", chat({ chat_template_kwargs: { enable_thinking: true } }, { chat_template_kwargs: { enable_thinking: false } })],
    ["undeclared", undefined],
    ["top-level-effort", chat({ reasoning_effort: "$EFFORT" })],
  ].map(([id, reasoning_params]) => ({ id, type: "chat", context_window: 8192, tool_calling: true, endpoints: ["/v1/chat/completions"], reasoning: true, reasoning_params }))
    .concat([{ id: "plain", type: "chat", context_window: 8192, tool_calling: true, endpoints: ["/v1/chat/completions"], reasoning: false, reasoning_params: undefined }]) });
  const kwargs = Object.fromEntries(models.map(m => [m.id, m.compat?.thinkingFormat === "chat-template" ? m.compat.chatTemplateKwargs : m.compat?.thinkingFormat]));
  assert.deepEqual(kwargs, {
    "effort-only": { reasoning_effort: { $var: "thinking.effort" }, thinking: enabled, enable_thinking: enabled },
    "declared-thinking": { reasoning_effort: { $var: "thinking.effort" }, thinking: enabled },
    "declared-enable": { enable_thinking: enabled },
    undeclared: { thinking: enabled, enable_thinking: enabled },
    "top-level-effort": undefined,
    plain: undefined,
  });
});

test("malformed or duplicate model identities invalidate the catalog", () => {
  assert.throws(() => parseNearCatalog({ data: [{ id: "ok" }, { id: "ok" }] }), /TEE_CATALOG_INVALID/);
  assert.throws(() => parseNearCatalog({ data: [{ id: "bad\nidentity" }] }), /TEE_CATALOG_INVALID/);
});
