import {
  createAssistantMessageEventStream, createProvider, envApiKeyAuth, lazyStream,
  openAICompletionsApi,
  type AssistantMessageEventStream, type Model, type Provider, type SimpleStreamOptions,
} from "@earendil-works/pi-ai/compat";
import { resolveModelVisibility, resolvePolicy, TeeError, type ModelVisibility, type PolicyMode } from "./policy.js";
import { guardChatFetch, readBoundedBody } from "./transport.js";

export interface SdkTransport {
  /** An adapter-owned endpoint selected after canonical-model preflight. */
  baseUrl?: string;
  fetch: typeof globalThis.fetch;
  dispose?(): void;
}

export type TeeCatalogModel = Model<"openai-completions"> & {
  /** Discovery metadata only; not attestation or independent workload approval. */
  teeCapability?: "declared" | "unsupported" | "unknown";
};

export interface ProviderDefinition {
  id: string;
  name: string;
  baseUrl: string;
  apiKeyEnv: string;
  policy?: PolicyMode;
  parseCatalog(value: unknown, context: { fetch: typeof globalThis.fetch; signal: AbortSignal }): TeeCatalogModel[] | Promise<TeeCatalogModel[]>;
  requireDeclaredTee?: boolean;
  modelVisibility?: ModelVisibility;
  catalogFetch?: typeof globalThis.fetch;
  availableModelIds?: readonly string[];
  openSdkTransport(options: { apiKey: string; signal: AbortSignal; model: TeeCatalogModel }): Promise<SdkTransport>;
  assumptions: readonly string[];
}

export interface ProviderReport {
  provider: string;
  policy: PolicyMode;
  lastRequest: "not-run" | "blocked" | "failed" | "sdk-accepted" | "aborted";
  reason?: string;
  catalogModels: number;
  modelVisibility?: ModelVisibility;
  declaredTeeModels?: number;
  catalogCheckedAt?: number;
  catalogError?: "TEE_CATALOG_FAILED";
  assumptions: readonly string[];
  independentApproval: "not-established";
  protectedSession: "not-established";
  closedTrustSet: "not-established";
}

const FOUR_HOURS = 4 * 60 * 60 * 1000;
const terminalCodes = new Set([
  "TEE_APPROVED_DEPLOYMENT_UNAVAILABLE", "TEE_MODEL_UNAVAILABLE", "TEE_API_KEY_REQUIRED",
  "TEE_RUNTIME_UNSUPPORTED", "TEE_REQUEST_REJECTED", "TEE_RESPONSE_REJECTED", "TEE_BODY_TOO_LARGE",
  "TEE_MODEL_ATTESTATION_UNAVAILABLE", "TEE_TLS_KEY_REJECTED", "TEE_WORKLOAD_PIN_REJECTED", "TEE_ATTESTATION_REJECTED",
  "TEE_VERIFIER_ARTIFACT_REJECTED", "TEE_VERIFIER_PROCESS_REJECTED", "TEE_CPU_POLICY_REJECTED", "TEE_GPU_POLICY_REJECTED",
]);

function safeFailure(source: AssistantMessageEventStream, report: ProviderReport, rejection: () => string | undefined, signal: AbortSignal): AssistantMessageEventStream {
  const output = createAssistantMessageEventStream();
  void (async () => {
    for await (const event of source) {
      if (signal.aborted && event.type !== "error") {
        const message = event.type === "done" ? event.message : event.partial;
        report.lastRequest = "aborted";
        report.reason = "TEE_REQUEST_ABORTED";
        output.push({ type: "error", reason: "aborted", error: { ...message, content: [], stopReason: "aborted", errorMessage: "TEE_REQUEST_ABORTED" } });
        break;
      }
      if (event.type === "error") {
        const known = event.error.errorMessage && terminalCodes.has(event.error.errorMessage) ? event.error.errorMessage : undefined;
        const aborted = signal.aborted || event.reason === "aborted";
        const code = aborted ? "TEE_REQUEST_ABORTED" : rejection() ?? known ?? "TEE_REQUEST_FAILED";
        report.lastRequest = aborted ? "aborted" : code === "TEE_APPROVED_DEPLOYMENT_UNAVAILABLE" ? "blocked" : "failed";
        report.reason = code;
        output.push({ ...event, reason: aborted ? "aborted" : "error", error: { ...event.error, content: [], stopReason: aborted ? "aborted" : "error", errorMessage: code } });
      } else {
        if (event.type === "done") {
          report.lastRequest = "sdk-accepted";
          delete report.reason;
        }
        output.push(event);
      }
    }
    output.end();
  })();
  return output;
}

export function createTeeProvider(definition: ProviderDefinition) {
  let mode = resolvePolicy(definition.policy);
  let visibility = resolveModelVisibility(definition.modelVisibility);
  let catalog: readonly TeeCatalogModel[] = [];
  let checkedAt: number | undefined;
  const report: ProviderReport = {
    provider: definition.id, policy: mode, lastRequest: "not-run", catalogModels: 0,
    assumptions: definition.assumptions, independentApproval: "not-established", protectedSession: "not-established", closedTrustSet: "not-established",
  };
  const active = new Set<AbortController>();
  const api = openAICompletionsApi();
  updateReport();

  const streams = {
    stream: (model: Model<"openai-completions">, context: Parameters<typeof api.stream>[1], options?: Parameters<typeof api.stream>[2]) =>
      run(model, options, (canonical, guarded) => api.stream(canonical, context, guarded)),
    streamSimple: (model: Model<"openai-completions">, context: Parameters<typeof api.streamSimple>[1], options?: SimpleStreamOptions) =>
      run(model, options, (canonical, guarded) => api.streamSimple(canonical, context, guarded)),
  };

  function run(
    requested: Model<"openai-completions">,
    options: SimpleStreamOptions | undefined,
    invoke: (model: Model<"openai-completions">, options: SimpleStreamOptions) => AssistantMessageEventStream,
  ) {
    const controller = new AbortController();
    let rejection: string | undefined;
    let transport: SdkTransport | undefined;
    const requestedTimeout = options?.timeoutMs;
    const timeout = typeof requestedTimeout === "number" && Number.isFinite(requestedTimeout) && requestedTimeout >= 0 ? Math.min(Math.floor(requestedTimeout), 600_000) : 600_000;
    const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(timeout), ...(options?.signal ? [options.signal] : [])]);
    active.add(controller);
    const source = lazyStream(requested, async () => {
      signal.throwIfAborted();
      if (mode !== "sdk") throw new TeeError("TEE_APPROVED_DEPLOYMENT_UNAVAILABLE");
      const canonical = catalog.find((entry) => entry.id === requested.id);
      if (!canonical || requested.provider !== definition.id || (definition.availableModelIds && !definition.availableModelIds.includes(canonical.id))) throw new TeeError("TEE_MODEL_UNAVAILABLE");
      if (definition.requireDeclaredTee && canonical.teeCapability !== "declared") throw new TeeError("TEE_MODEL_ATTESTATION_UNAVAILABLE");
      if (!options?.apiKey) throw new TeeError("TEE_API_KEY_REQUIRED");
      transport = await definition.openSdkTransport({ apiKey: options.apiKey, signal, model: structuredClone(canonical) });
      signal.throwIfAborted();
      const baseUrl = transport.baseUrl ?? definition.baseUrl;
      const endpoint = new URL(baseUrl);
      if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
          endpoint.pathname !== "/v1" || endpoint.href !== `${endpoint.origin}/v1`) throw new TeeError("TEE_REQUEST_REJECTED");
      const fetch = guardChatFetch({
        fetch: transport.fetch, endpoint: `${baseUrl}/chat/completions`, model: canonical.id,
        apiKey: options.apiKey, signal, onRejection: () => { rejection = "TEE_REQUEST_REJECTED"; },
      });
      return invoke({ ...canonical, baseUrl }, { ...options, signal, fetch, maxRetries: 0, headers: undefined, sessionId: undefined, cacheRetention: "none" });
    });
    const result = safeFailure(source, report, () => rejection, signal);
    void result.result().then(() => {
      active.delete(controller);
      transport?.dispose?.();
    });
    return result;
  }

  const base = createProvider<"openai-completions">({
    id: definition.id, name: definition.name, baseUrl: definition.baseUrl,
    models: [], api: streams,
    auth: { apiKey: envApiKeyAuth(`${definition.name} API key`, [definition.apiKeyEnv]) },
  });
  const provider: Provider<"openai-completions"> = {
    ...base,
    getModels: () => mode === "sdk" ? structuredClone(visibleCatalog()) : [],
    getAllModels: () => mode === "sdk" ? structuredClone(visibleCatalog()) : [],
    refreshModels: async (context) => {
      if (context.stored && (checkedAt === undefined || (context.stored.checkedAt ?? 0) > checkedAt)) {
        // Stored metadata never chooses the transport origin or caller headers.
        const restored = context.stored.models.filter((entry): entry is Model<"openai-completions"> =>
          entry.provider === definition.id && entry.api === "openai-completions" && typeof entry.id === "string");
        await context.publish({ update: () => { catalog = restored.map((entry) => ({ ...entry, baseUrl: definition.baseUrl, headers: undefined })); checkedAt = context.stored?.checkedAt; updateReport(); } });
      }
      if (checkedAt !== undefined && (context.stored?.checkedAt ?? 0) < checkedAt) {
        await context.publish({ persist: { models: [...catalog], checkedAt } });
      }
      if (!context.allowNetwork || context.signal.aborted) return;
      if (!context.force && checkedAt !== undefined && Date.now() - checkedAt < FOUR_HOURS) return;
      let models: Model<"openai-completions">[];
      try { models = await fetchCatalog(context.signal); }
      catch { report.catalogError = "TEE_CATALOG_FAILED"; throw new TeeError("TEE_CATALOG_FAILED"); }
      const now = Date.now();
      await context.publish({
        persist: { models, checkedAt: now },
        update: () => { catalog = models; checkedAt = now; delete report.catalogError; updateReport(); },
      });
    },
  };

  function visibleCatalog() {
    return catalog.filter((entry) => (!definition.availableModelIds || definition.availableModelIds.includes(entry.id)) &&
      (!definition.requireDeclaredTee || visibility === "all" || entry.teeCapability === "declared")).map((entry) => {
      if (!definition.requireDeclaredTee || entry.teeCapability === "declared") return entry;
      const label = entry.teeCapability === "unsupported" ? "non-TEE" : "TEE unknown";
      return { ...entry, name: `${entry.name} [${label}; inference blocked]` };
    });
  }

  function updateReport() {
    report.catalogModels = catalog.length;
    report.catalogCheckedAt = checkedAt;
    if (definition.requireDeclaredTee) {
      report.modelVisibility = visibility;
      report.declaredTeeModels = catalog.filter((entry) => entry.teeCapability === "declared").length;
    }
  }

  async function fetchCatalog(signal: AbortSignal) {
    const bounded = AbortSignal.any([signal, AbortSignal.timeout(8000)]);
    const response = await (definition.catalogFetch ?? globalThis.fetch)(`${definition.baseUrl}/models`, { signal: bounded, redirect: "error" });
    if (!response.ok) throw new TeeError("TEE_CATALOG_FAILED");
    const bytes = await readBoundedBody(response.body, 2 * 1024 * 1024, bounded);
    return structuredClone(await definition.parseCatalog(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)), {
      fetch: definition.catalogFetch ?? globalThis.fetch, signal: bounded,
    }));
  }

  return {
    provider,
    async initializeCatalog(signal = AbortSignal.timeout(8000)) {
      try { catalog = await fetchCatalog(signal); }
      catch { report.catalogError = "TEE_CATALOG_FAILED"; throw new TeeError("TEE_CATALOG_FAILED"); }
      checkedAt = Date.now();
      delete report.catalogError;
      updateReport();
    },
    setPolicy(value: string) {
      const next = resolvePolicy(value);
      if (next !== mode) for (const controller of active) controller.abort();
      mode = next;
      report.policy = next;
      report.lastRequest = "not-run";
      delete report.reason;
    },
    setModelVisibility(value: string) {
      visibility = resolveModelVisibility(value);
      updateReport();
    },
    getReport: (): ProviderReport => structuredClone(report),
    getDiscoveredModels: () => visibleCatalog().map((entry) => ({
      id: entry.id, name: entry.name,
      ...(definition.requireDeclaredTee ? { teeCapability: entry.teeCapability ?? "unknown" } : {}),
      selectable: mode === "sdk" && (!definition.requireDeclaredTee || entry.teeCapability === "declared"),
    })),
  };
}
