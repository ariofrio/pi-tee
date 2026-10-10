import assert from "node:assert/strict";
import { test } from "node:test";
import { getSupportedThinkingLevels, normalizeContext, openAICompletionsApi, type Model } from "@earendil-works/pi-ai/compat";
import { parseChutesCatalog } from "../packages/chutes/src/catalog.js";
import { parseNearCatalog } from "../packages/nearai/src/catalog.js";
import { parseTinfoilCatalog } from "../packages/tinfoil/src/catalog.js";
import { privatemodeCatalog, SHIPPED_CATALOG } from "../packages/privatemode/src/catalog.js";

type Level = "off" | "low" | "medium" | "high" | "xhigh" | "max";

/** The reasoning fields Pi serializes for a level, observed at the fetch seam. */
async function sent(model: Model<"openai-completions">, level: Level) {
  let body: Record<string, unknown> = {};
  await openAICompletionsApi().streamSimple(model, normalizeContext({ messages: [{ role: "user", content: "synthetic", timestamp: 1 }] }), {
    apiKey: "fixture-key", ...(level === "off" ? {} : { reasoning: level }),
    fetch: async (input, init) => {
      body = await new Request(input, init).json() as Record<string, unknown>;
      return new Response('data: {"id":"fixture","choices":[{"index":0,"delta":{"content":"OK"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n',
        { headers: { "content-type": "text/event-stream" } });
    },
  }).result();
  return { kwargs: body.chat_template_kwargs, effort: body.reasoning_effort };
}

const chutes = (id: string) => parseChutesCatalog({ data: [{ id, chute_id: "08901219-159f-55a7-87cf-9d0d02744668", confidential_compute: true,
  context_length: 8192, max_output_length: 1024, supported_features: ["tools", "reasoning"] }] })[0]!;
const near = (id: string) => parseNearCatalog({ data: [{ id, context_length: 8192, supported_features: ["tools", "reasoning"] }] })[0]!;
const tinfoil = (id: string, reasoning_params?: unknown) => parseTinfoilCatalog({ data: [{ id, type: "chat", tool_calling: true,
  endpoints: ["/v1/chat/completions"], context_window: 8192, reasoning: true, reasoning_params }] })[0]!;
const on = { thinking: true, enable_thinking: true };
const off = { thinking: false, enable_thinking: false };

test("Pi's thinking level selects each known template's own effort, inside chat_template_kwargs", async () => {
  const cases: [Model<"openai-completions">, Partial<Record<Level, unknown>>][] = [
    [chutes("Qwen/Qwen3.8-27B-TEE"), { off, low: { ...on, reasoning_effort: "low" }, medium: { ...on, reasoning_effort: "medium" }, high: { ...on, reasoning_effort: "xhigh" } }],
    [near("Qwen/Qwen3.8-27B"), { high: { ...on, reasoning_effort: "xhigh" } }],
    [chutes("moonshotai/Kimi-K3-TEE"), { off, low: { ...on, thinking_effort: "low" }, medium: { ...on, thinking_effort: "high" }, high: { ...on, thinking_effort: "high" }, max: { ...on, thinking_effort: "max" } }],
    [tinfoil("kimi-k3"), { off, high: { ...on, thinking_effort: "high" } }],
    [near("z-ai/glm-5.3-flash"), { off: { reasoning_effort: "low" }, low: { reasoning_effort: "low" }, medium: { reasoning_effort: "high" }, high: { reasoning_effort: "high" }, max: { reasoning_effort: "max" } }],
    [chutes("zai-org/GLM-5.2-TEE"), { low: { ...on, reasoning_effort: "high" }, high: { ...on, reasoning_effort: "high" }, max: { ...on, reasoning_effort: "max" } }],
  ];
  for (const [model, expected] of cases) {
    for (const [level, kwargs] of Object.entries(expected)) {
      assert.deepEqual(await sent(model, level as Level), { kwargs, effort: undefined }, `${model.id} ${level}`);
    }
  }
});

test("Pi offers only the extra-high levels a known template names", () => {
  assert.deepEqual(getSupportedThinkingLevels(chutes("Qwen/Qwen3.8-27B-TEE")), ["off", "minimal", "low", "medium", "high", "xhigh"]);
  assert.deepEqual(getSupportedThinkingLevels(chutes("moonshotai/Kimi-K3-TEE")), ["off", "minimal", "low", "medium", "high", "max"]);
  assert.deepEqual(getSupportedThinkingLevels(chutes("Qwen/Qwen3.6-27B-TEE")), ["off", "minimal", "low", "medium", "high"]);
});

test("Unknown and on/off-only reasoning models keep only the thinking switch", async () => {
  for (const model of [chutes("Qwen/Qwen3.6-27B-TEE"), chutes("vendor/Unknown-TEE"), near("vendor/kimi-k3-preview"), tinfoil("unknown-chat")]) {
    assert.deepEqual(await sent(model, "high"), { kwargs: on, effort: undefined }, model.id);
    assert.deepEqual(await sent(model, "off"), { kwargs: off, effort: undefined }, model.id);
  }
});

test("GLM-5.3 always thinks, so Tinfoil sends its weakest effort for off instead of a switch", async () => {
  const glm = tinfoil("glm-5-3", { effort_map: { high: "max", low: "low", medium: "high" },
    params: { "/v1/chat/completions": { enable: { chat_template_kwargs: { reasoning_effort: "$EFFORT" } } } } });
  assert.deepEqual(await sent(glm, "high"), { kwargs: { reasoning_effort: "high" }, effort: undefined });
  assert.deepEqual(await sent(glm, "max"), { kwargs: { reasoning_effort: "max" }, effort: undefined });
  assert.deepEqual(await sent(glm, "off"), { kwargs: { reasoning_effort: "low" }, effort: undefined });
});

test("Tinfoil's effort map names the template's efforts; Pi's levels select them by name", async () => {
  const ds = tinfoil("deepseek-v4-1-flash", { effort_map: { high: "xhigh", low: "low", medium: "high" },
    params: { "/v1/chat/completions": { enable: { chat_template_kwargs: { reasoning_effort: "$EFFORT", thinking: true } } } } });
  assert.deepEqual(getSupportedThinkingLevels(ds), ["off", "minimal", "low", "medium", "high", "xhigh"]);
  const efforts = Object.fromEntries(await Promise.all((["low", "medium", "high", "xhigh"] as const).map(async l => [l, await sent(ds, l)])));
  assert.deepEqual(efforts, {
    low: { kwargs: { reasoning_effort: "low", thinking: true }, effort: undefined },
    medium: { kwargs: { reasoning_effort: "high", thinking: true }, effort: undefined },
    high: { kwargs: { reasoning_effort: "high", thinking: true }, effort: undefined },
    xhigh: { kwargs: { reasoning_effort: "xhigh", thinking: true }, effort: undefined },
  });
  assert.deepEqual(await sent(ds, "off"), { kwargs: { thinking: false }, effort: undefined });
});

test("Privatemode GLM effort follows the template's own names; off selects its weakest effort", async () => {
  const glm = privatemodeCatalog(SHIPPED_CATALOG).find(m => m.id === "glm-5.3")!;
  const efforts = Object.fromEntries(await Promise.all((["off", "low", "medium", "high", "max"] as const).map(async l => [l, (await sent(glm, l)).effort])));
  assert.deepEqual(efforts, { off: "low", low: "low", medium: "high", high: "high", max: "max" });
});

test("Chutes DeepSeek-V4-Flash-0731 receives its serving profile's effort as a top-level field", async () => {
  const ds = chutes("deepseek-ai/DeepSeek-V4-Flash-0731-TEE");
  assert.deepEqual(getSupportedThinkingLevels(ds), ["off", "minimal", "low", "medium", "high"]);
  const efforts = Object.fromEntries(await Promise.all((["off", "low", "medium", "high"] as const).map(async l => [l, await sent(ds, l)])));
  assert.deepEqual(efforts, {
    off: { kwargs: undefined, effort: "none" }, low: { kwargs: undefined, effort: "high" },
    medium: { kwargs: undefined, effort: "high" }, high: { kwargs: undefined, effort: "max" },
  });
  for (const model of [near("deepseek-ai/DeepSeek-V4-Flash-0731"), chutes("deepseek-ai/DeepSeek-V4-Flash-TEE")]) {
    assert.deepEqual(await sent(model, "high"), { kwargs: on, effort: undefined }, model.id);
  }
});
