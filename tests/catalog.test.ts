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
  assert.deepEqual(model?.compat?.chatTemplateKwargs, { reasoning_effort: { $var: "thinking.effort" } });
  assert.equal(model?.thinkingLevelMap?.high, "max");
});

test("malformed or duplicate model identities invalidate the catalog", () => {
  assert.throws(() => parseNearCatalog({ data: [{ id: "ok" }, { id: "ok" }] }), /TEE_CATALOG_INVALID/);
  assert.throws(() => parseNearCatalog({ data: [{ id: "bad\nidentity" }] }), /TEE_CATALOG_INVALID/);
});
