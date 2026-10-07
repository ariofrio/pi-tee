import type { Model } from "@earendil-works/pi-ai/compat";
import { TeeError } from "./policy.js";

export function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

export function entries(value: unknown): Record<string, unknown>[] {
  const data = record(value).data;
  if (!Array.isArray(data) || data.length > 2000) throw new TeeError("TEE_CATALOG_INVALID");
  const ids = new Set<string>();
  return data.map((entry) => {
    const raw = record(entry);
    if (typeof raw.id !== "string" || !/^[A-Za-z0-9_./:@+-]{1,200}$/.test(raw.id) || ids.has(raw.id)) {
      throw new TeeError("TEE_CATALOG_INVALID");
    }
    ids.add(raw.id);
    return raw;
  });
}

export function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

export function price(value: unknown): number | undefined {
  if (typeof value !== "string" && typeof value !== "number") return undefined;
  const number = Number(value);
  return value !== "" && Number.isFinite(number) && number >= 0 ? number : undefined;
}

export function catalogModel(options: {
  provider: string; baseUrl: string; id: string; name: unknown; contextWindow: unknown;
  maxTokens: unknown; reasoning: boolean; image: boolean;
  cost: { input?: number; output?: number; cacheRead?: number };
}): Model<"openai-completions"> {
  const contextWindow = Number(options.contextWindow);
  const suppliedMax = Number(options.maxTokens);
  if (!Number.isSafeInteger(contextWindow) || contextWindow < 128 || contextWindow > 10_000_000) {
    throw new TeeError("TEE_CATALOG_INVALID");
  }
  const maxTokens = Number.isSafeInteger(suppliedMax) && suppliedMax > 0
    ? Math.min(suppliedMax, contextWindow) : Math.min(32768, Math.max(1, Math.floor(contextWindow / 8)));
  const name = (typeof options.name === "string" ? options.name : options.id).replace(/[\u0000-\u001f\u007f-\u009f]/g, "").slice(0, 200);
  const pricingKnown = options.cost.input !== undefined && options.cost.output !== undefined;
  return {
    id: options.id, name: pricingKnown ? name : `${name} (pricing unavailable)`, provider: options.provider,
    api: "openai-completions", baseUrl: options.baseUrl, contextWindow, maxTokens,
    reasoning: options.reasoning, input: options.image ? ["text", "image"] : ["text"],
    cost: { input: options.cost.input ?? 0, output: options.cost.output ?? 0, cacheRead: options.cost.cacheRead ?? 0, cacheWrite: 0 },
    compat: {
      supportsStore: false, supportsDeveloperRole: false, supportsUsageInStreaming: true,
      supportsReasoningEffort: false, supportsFinishReason: true, supportsOpenAIGrammarTools: false,
      sendSessionAffinityHeaders: false, supportsStrictMode: false, maxTokensField: "max_tokens",
    },
  };
}
