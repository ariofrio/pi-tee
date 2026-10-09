import { catalogModel, chatTemplateThinking, entries, nativeEffortLevels, price, record, strings } from "pi-tee-core";
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
  const declaredSwitch: Record<string, { $var: "thinking.enabled" }> = {};
  for (const [key, value] of Object.entries(kwargs)) {
    if (key === "reasoning_effort" && value === "$EFFORT") mapped[key] = { $var: "thinking.effort" };
    else if ((key === "enable_thinking" || key === "thinking") && typeof value === "boolean") declaredSwitch[key] = { $var: "thinking.enabled" };
    else if (key === "clear_thinking" && typeof value === "boolean") mapped[key] = value;
  }
  // Some chat-template models declare only an effort, or nothing, yet think by default;
  // without a switch Pi's "off" would leave thinking on. A known template's own effort
  // names replace the declared effort map.
  const topLevel = record(enable.thinking).type === "enabled" || enable.reasoning_effort === "$EFFORT";
  const native = model.reasoning && !topLevel ? chatTemplateThinking(model.id, Object.keys(declaredSwitch).length ? declaredSwitch : undefined) : undefined;
  if (native?.thinkingLevelMap) delete mapped.reasoning_effort;
  Object.assign(mapped, native?.chatTemplateKwargs ?? declaredSwitch);
  if (Object.keys(mapped).length) model.compat = { ...model.compat, thinkingFormat: "chat-template", chatTemplateKwargs: mapped };
  else if (record(enable.thinking).type === "enabled") model.compat = { ...model.compat, thinkingFormat: "deepseek", supportsReasoningEffort: enable.reasoning_effort === "$EFFORT" };
  else if (enable.reasoning_effort === "$EFFORT") model.compat = { ...model.compat, supportsReasoningEffort: true };
  if (native?.thinkingLevelMap) {
    model.thinkingLevelMap = native.thinkingLevelMap;
    return;
  }
  // The effort map's values are the template's own names. Pi's levels map to the same
  // name where it exists, as on other hosts, rather than to Tinfoil's stronger choices.
  const effortMap = record(params.effort_map);
  const levels = ["minimal", "low", "medium", "high", "xhigh", "max"];
  const declared = Object.values(effortMap);
  const named = levels.filter(level => declared.includes(level));
  if (declared.length && named.length === new Set(declared).size) {
    model.thinkingLevelMap = nativeEffortLevels(named);
    return;
  }
  const thinkingLevelMap: NonNullable<Model<"openai-completions">["thinkingLevelMap"]> = {};
  for (const level of ["minimal", "low", "medium", "high", "xhigh"] as const) {
    const value = effortMap[level];
    if (typeof value === "string" && /^[a-z]{1,20}$/.test(value)) thinkingLevelMap[level] = value;
  }
  if (Object.keys(thinkingLevelMap).length) model.thinkingLevelMap = thinkingLevelMap;
}
