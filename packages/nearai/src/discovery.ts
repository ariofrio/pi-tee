import { readBoundedBody, record, withAbort, type TeeCatalogModel } from "pi-tee-core";
import { NEAR_BASE_URL, parseNearCatalog } from "./catalog.js";

export async function loadNearCatalog(value: unknown, context: {
  fetch: typeof globalThis.fetch;
  signal: AbortSignal;
}): Promise<TeeCatalogModel[]> {
  const models: TeeCatalogModel[] = parseNearCatalog(value);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(4, models.length) }, async () => {
    while (next < models.length) {
      context.signal.throwIfAborted();
      const model = models[next++]!;
      model.teeCapability = "unknown";
      model.sdkTransportAvailable = false;
      if (model.id === "." || model.id === "..") continue;
      const signal = AbortSignal.any([context.signal, AbortSignal.timeout(3000)]);
      try {
        const response = await withAbort(context.fetch(`${NEAR_BASE_URL}/model/${encodeURIComponent(model.id)}`, { signal, redirect: "error" }), signal);
        if (!response.ok) { void response.body?.cancel().catch(() => undefined); continue; }
        const bytes = await readBoundedBody(response.body, 64 * 1024, signal);
        const detail = record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
        const metadata = record(detail.metadata);
        if (detail.modelId !== model.id || typeof metadata.providerType !== "string" || typeof metadata.attestationSupported !== "boolean") continue;
        model.teeCapability = metadata.attestationSupported ? "declared" : "unsupported";
        model.sdkTransportAvailable = metadata.providerType === "vllm" && metadata.attestationSupported;
      } catch { /* Missing or malformed capability stays unknown and hidden by default. */ }
    }
  }));
  context.signal.throwIfAborted();
  return models;
}

export const NEAR_ENDPOINT_REGISTRY = "https://completions.near.ai/endpoints";
export const NEAR_DIRECT_HOST = /^[a-z0-9-]+\.completions\.near\.ai$/;

/** Provider claims select candidates only; request evidence alone establishes levels. */
export async function discoverNearDirectEndpoints(models: readonly TeeCatalogModel[], context: {
  fetch: typeof globalThis.fetch; signal: AbortSignal;
}): Promise<Map<string, string[]>> {
  const read = async (url: string) => {
    const response = await withAbort(context.fetch(url, { signal: context.signal, redirect: "error" }), context.signal);
    if (!response.ok) { void response.body?.cancel().catch(() => undefined); throw new Error("discovery unavailable"); }
    return record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(response.body, 2 * 1024 * 1024, context.signal))));
  };
  const [first, registry] = await Promise.all([read(`${NEAR_BASE_URL}/model/list`), read(NEAR_ENDPOINT_REGISTRY)]);
  const details: Record<string, unknown>[] = [];
  let page = first;
  for (let pages = 0; ; pages++) {
    if (!Array.isArray(page.models) || page.offset !== details.length || !Number.isSafeInteger(page.total) ||
        (page.total as number) < details.length + page.models.length || page.total !== first.total) throw new Error("invalid catalog pagination");
    details.push(...page.models.map(record));
    if (details.length === page.total) break;
    if (!page.models.length || pages >= 9) throw new Error("incomplete catalog");
    page = await read(`${NEAR_BASE_URL}/model/list?offset=${details.length}&limit=100`);
  }
  if (!Array.isArray(registry.endpoints)) throw new Error("invalid endpoint registry");
  const eligible = new Set(models.filter(model => model.teeCapability === "declared").map(model => model.id));
  const declared = new Set(details.filter(detail => {
    const metadata = record(detail.metadata);
    return eligible.has(detail.modelId as string) && metadata.attestationSupported === true &&
      Array.isArray(metadata.supportedFeatures) && metadata.supportedFeatures.includes("tools");
  }).map(detail => detail.modelId as string));
  const endpoints = new Map<string, string[]>();
  for (const raw of registry.endpoints) {
    const entry = record(raw);
    if (typeof entry.domain !== "string" || !NEAR_DIRECT_HOST.test(entry.domain) || !Array.isArray(entry.models)) continue;
    for (const id of entry.models) {
      if (typeof id !== "string" || !declared.has(id)) continue;
      const hosts = endpoints.get(id) ?? [];
      if (!hosts.includes(entry.domain)) hosts.push(entry.domain);
      endpoints.set(id, hosts);
    }
  }
  return endpoints;
}
