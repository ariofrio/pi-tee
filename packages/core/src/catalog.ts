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

/** Open-weight chat templates name their thinking switch either way and ignore the
 * other; hosts that ignore Pi's effort level still honor this on/off switch. */
export function thinkingSwitch() {
  const enabled = { $var: "thinking.enabled" } as const;
  return { thinking: enabled, enable_thinking: enabled };
}

const EFFORTS = ["minimal", "low", "medium", "high", "xhigh", "max"] as const;
type Effort = typeof EFFORTS[number];
type NativeEffort = { kwarg: "reasoning_effort" | "thinking_effort"; levels: readonly Effort[]; canDisable: boolean };

/** Effort controls of open-weight chat templates, keyed by `templateFamily()`. Hosts
 * expose no template metadata, so these are read from the published templates; a
 * template that rejects or ignores other names cannot be probed safely. Models not
 * listed keep only the on/off switch. `canDisable` is false where the template always
 * thinks, so a switch would only stop the host from separating the reasoning. */
const NATIVE_EFFORT: Record<string, NativeEffort> = {
  "qwen3-8-27b": { kwarg: "reasoning_effort", levels: ["low", "medium", "xhigh"], canDisable: true },
  "glm-5-2": { kwarg: "reasoning_effort", levels: ["high", "max"], canDisable: true },
  "glm-5-3": { kwarg: "reasoning_effort", levels: ["low", "high", "max"], canDisable: false },
  "glm-5-3-flash": { kwarg: "reasoning_effort", levels: ["low", "high", "max"], canDisable: false },
  "kimi-k3": { kwarg: "thinking_effort", levels: ["low", "high", "max"], canDisable: true },
};

function templateFamily(id: string) {
  return (id.split("/").pop() ?? "").toLowerCase().replace(/-tee$/, "").replaceAll(".", "-");
}

/** Maps each Pi level to the template's level of the same name, else the next stronger
 * one, else its strongest. Pi offers xhigh and max only where the template names them. */
export function nativeEffortLevels(levels: readonly string[], off?: string): NonNullable<Model<"openai-completions">["thinkingLevelMap"]> {
  const map: NonNullable<Model<"openai-completions">["thinkingLevelMap"]> = off === undefined ? {} : { off };
  EFFORTS.forEach((level, rank) => {
    if (levels.includes(level)) map[level] = level;
    else if (level !== "xhigh" && level !== "max") {
      map[level] = levels.find(native => EFFORTS.indexOf(native as Effort) > rank) ?? levels.at(-1);
    }
  });
  return map;
}

/** Chat-template thinking controls for a reasoning model: its native effort where the
 * template is known, and an on/off switch where the template can disable thinking. */
export function chatTemplateThinking(id: string, declaredSwitch?: Record<string, { $var: "thinking.enabled" }>) {
  const native = Object.hasOwn(NATIVE_EFFORT, templateFamily(id)) ? NATIVE_EFFORT[templateFamily(id)] : undefined;
  if (!native) return { chatTemplateKwargs: declaredSwitch ?? thinkingSwitch() };
  return {
    chatTemplateKwargs: { ...(native.canDisable ? declaredSwitch ?? thinkingSwitch() : {}), [native.kwarg]: { $var: "thinking.effort" } as const },
    thinkingLevelMap: nativeEffortLevels(native.levels, native.canDisable ? undefined : native.levels[0]),
  };
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
