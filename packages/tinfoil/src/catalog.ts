import { catalogModel, entries, price, record, strings } from "@ariofrio/pi-tee-core";
import type { Model, OpenAICompletionsCompat } from "@earendil-works/pi-ai/compat";

export const TINFOIL_BASE_URL = "https://inference.tinfoil.sh/v1";

export function parseTinfoilCatalog(value: unknown) {
  return entries(value).filter((raw) => raw.type === "chat" && raw.tool_calling === true &&
    strings(raw.endpoints).includes("/v1/chat/completions")).map((raw) => {
    const pricing = record(raw.pricing);
    const model = catalogModel({
      provider: "tinfoil", baseUrl: TINFOIL_BASE_URL, id: raw.id as string, name: raw.name,
      contextWindow: raw.context_window, maxTokens: raw.max_tokens, reasoning: raw.reasoning === true, image: raw.multimodal === true,
      cost: { input: price(pricing.inputTokenPricePer1M), output: price(pricing.outputTokenPricePer1M), cacheRead: price(pricing.cachedInputTokenPricePer1M) },
    });
    applyThinking(model, record(raw.reasoning_params));
    return model;
  });
}

function applyThinking(model: Model<"openai-completions">, params: Record<string, unknown>) {
  const chat = record(record(params.params)["/v1/chat/completions"]);
  const enable = record(chat.enable);
  const kwargs = record(enable.chat_template_kwargs);
  const mapped: NonNullable<OpenAICompletionsCompat["chatTemplateKwargs"]> = {};
  for (const [key, value] of Object.entries(kwargs)) {
    if (key === "reasoning_effort" && value === "$EFFORT") mapped[key] = { $var: "thinking.effort" };
    else if (key === "enable_thinking" && typeof value === "boolean") mapped[key] = { $var: "thinking.enabled" };
    else if (key === "clear_thinking" && typeof value === "boolean") mapped[key] = value;
  }
  if (Object.keys(mapped).length) model.compat = { ...model.compat, thinkingFormat: "chat-template", chatTemplateKwargs: mapped };
  else if (record(enable.thinking).type === "enabled") model.compat = { ...model.compat, thinkingFormat: "deepseek", supportsReasoningEffort: enable.reasoning_effort === "$EFFORT" };
  else if (enable.reasoning_effort === "$EFFORT") model.compat = { ...model.compat, supportsReasoningEffort: true };
  const effortMap = record(params.effort_map);
  const thinkingLevelMap: NonNullable<Model<"openai-completions">["thinkingLevelMap"]> = {};
  for (const level of ["minimal", "low", "medium", "high", "xhigh"] as const) {
    const value = effortMap[level];
    if (typeof value === "string" && /^[a-z]{1,20}$/.test(value)) thinkingLevelMap[level] = value;
  }
  if (Object.keys(thinkingLevelMap).length) model.thinkingLevelMap = thinkingLevelMap;
}
