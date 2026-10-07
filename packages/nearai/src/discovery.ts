import { readBoundedBody, record, withAbort, type TeeCatalogModel } from "@ariofrio/pi-tee-core";
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
      if (model.id === "." || model.id === "..") continue;
      const signal = AbortSignal.any([context.signal, AbortSignal.timeout(3000)]);
      try {
        const response = await withAbort(context.fetch(`${NEAR_BASE_URL}/model/${encodeURIComponent(model.id)}`, { signal, redirect: "error" }), signal);
        if (!response.ok) { void response.body?.cancel().catch(() => undefined); continue; }
        const bytes = await readBoundedBody(response.body, 64 * 1024, signal);
        const detail = record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
        const metadata = record(detail.metadata);
        if (detail.modelId !== model.id || typeof metadata.providerType !== "string" || typeof metadata.attestationSupported !== "boolean") continue;
        model.teeCapability = metadata.providerType === "vllm" && metadata.attestationSupported === true ? "declared" : "unsupported";
      } catch { /* Missing or malformed capability stays unknown and hidden by default. */ }
    }
  }));
  context.signal.throwIfAborted();
  return models;
}
