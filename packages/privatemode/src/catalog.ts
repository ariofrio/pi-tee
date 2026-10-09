import { catalogModel, entries, nativeEffortLevels, strings } from "pi-tee-core";
import { PRIVATEMODE_BASE_URL } from "./wire.js";
// Versioned catalog claims. The authenticated /v1/models endpoint needs a key;
// catalog startup must not bootstrap with an unstored credential.
export const PRIVATEMODE_MODELS = [
  "glm-5.3",
  "glm-5.3-flash",
  "gpt-oss-120b",
] as const;
export const SHIPPED_CATALOG = {
  data: PRIVATEMODE_MODELS.map((id) => ({
    id,
    tasks: [
      "generate",
      "tool_calling",
      ...(id === "glm-5.3-flash" ? ["vision"] : []),
    ],
  })),
};
export function privatemodeCatalog(value: unknown) {
  return entries(value)
    .filter(
      (raw) =>
        PRIVATEMODE_MODELS.includes(
          raw.id as (typeof PRIVATEMODE_MODELS)[number],
        ) &&
        strings(raw.tasks).includes("generate") &&
        strings(raw.tasks).includes("tool_calling"),
    )
    .map((raw) => {
      const id = raw.id as string;
      const model = catalogModel({
        provider: "privatemode",
        baseUrl: PRIVATEMODE_BASE_URL,
        id,
        name: id,
        contextWindow: id === "gpt-oss-120b" ? 131072 : 1048576,
        maxTokens: 32768,
        reasoning: true,
        image: strings(raw.tasks).includes("vision"),
        cost: {},
      });
      model.compat = {
        ...model.compat,
        maxTokensField: "max_completion_tokens",
        supportsReasoningEffort: true,
      };
      // These effort-only APIs cannot disable reasoning, so off selects the weakest effort.
      model.thinkingLevelMap = nativeEffortLevels(
        id === "gpt-oss-120b" ? ["low", "medium", "high"] : ["low", "high", "max"],
        "low",
      );
      return model;
    });
}
