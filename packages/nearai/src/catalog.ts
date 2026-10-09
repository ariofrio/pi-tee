import { catalogModel, chatTemplateThinking, entries, price, record, strings } from "pi-tee-core";

export const NEAR_BASE_URL = "https://cloud-api.near.ai/v1";

export function parseNearCatalog(value: unknown) {
  return entries(value).filter((raw) => strings(raw.supported_features).includes("tools") &&
    (!raw.output_modalities || strings(raw.output_modalities).includes("text"))).map((raw) => {
    const pricing = record(raw.pricing);
    const model = catalogModel({
      provider: "nearai", baseUrl: NEAR_BASE_URL, id: raw.id as string, name: raw.name,
      // NEAR does not enforce max_output_length; context is the real bound, and
      // Pi clamps max_tokens to the remaining context.
      contextWindow: raw.context_length, maxTokens: raw.context_length,
      reasoning: strings(raw.supported_features).includes("reasoning"),
      image: strings(raw.input_modalities ?? record(raw.architecture).inputModalities).includes("image"),
      cost: {
        input: price(pricing.input) ?? (price(pricing.prompt) === undefined ? undefined : price(pricing.prompt)! * 1_000_000),
        output: price(pricing.output) ?? (price(pricing.completion) === undefined ? undefined : price(pricing.completion)! * 1_000_000),
        cacheRead: price(pricing.input_cache_read) === undefined ? undefined : price(pricing.input_cache_read)! * 1_000_000,
      },
    });
    model.compat = { ...model.compat, maxTokensField: "max_completion_tokens" };
    // Templates refuse effort names they do not define, so effort goes only to known ones.
    if (model.reasoning) {
      const { chatTemplateKwargs, thinkingLevelMap } = chatTemplateThinking(model.id);
      model.compat = { ...model.compat, thinkingFormat: "chat-template", chatTemplateKwargs };
      if (thinkingLevelMap) model.thinkingLevelMap = thinkingLevelMap;
    }
    return model;
  });
}
