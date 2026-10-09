import { catalogModel, chatTemplateThinking, entries, price, record, strings, type TeeCatalogModel } from "pi-tee-core";

export const CHUTES_BASE_URL = "https://llm.chutes.ai/v1";
export const CHUTES_API_URL = "https://api.chutes.ai";
export const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

export function parseChutesCatalog(value: unknown): TeeCatalogModel[] {
  return entries(value).filter(raw => raw.confidential_compute === true && UUID.test(String(raw.chute_id)) &&
    strings(raw.supported_features).includes("tools") && (!raw.output_modalities || strings(raw.output_modalities).includes("text"))).map(raw => {
    const pricing = record(raw.pricing);
    const model: TeeCatalogModel = catalogModel({
      provider: "chutes", baseUrl: CHUTES_BASE_URL, id: raw.id as string, name: raw.id,
      contextWindow: raw.context_length, maxTokens: raw.max_output_length,
      reasoning: strings(raw.supported_features).includes("reasoning"), image: strings(raw.input_modalities).includes("image"),
      cost: { input: price(pricing.prompt), output: price(pricing.completion), cacheRead: price(pricing.input_cache_read) },
    });
    model.teeCapability = "declared";
    model.sdkTransportAvailable = true;
    // Templates refuse effort names they do not define, so effort goes only to known ones.
    if (model.reasoning) {
      const { chatTemplateKwargs, thinkingLevelMap } = chatTemplateThinking(model.id);
      model.compat = { ...model.compat, thinkingFormat: "chat-template", chatTemplateKwargs };
      if (thinkingLevelMap) model.thinkingLevelMap = thinkingLevelMap;
    }
    return model;
  });
}
