import assert from "node:assert/strict";
import { test } from "node:test";
import { createNearProvider } from "../packages/nearai/src/index.js";
import { normalizeContext } from "@earendil-works/pi-ai/compat";

const rawModels = ["local/tee", "external/zdr", "unknown/model"].map((id) => ({
  id, name: id, context_length: 8192, supported_features: ["tools"], output_modalities: ["text"],
}));
const catalogFetch: typeof globalThis.fetch = async (input) => {
  const url = String(input);
  if (url.endsWith("/models")) return Response.json({ data: rawModels });
  const id = decodeURIComponent(url.split("/model/")[1]!);
  if (id === "unknown/model") return new Response(null, { status: 503 });
  return Response.json({ modelId: id, metadata: {
    providerType: id === "local/tee" ? "vllm" : "external", attestationSupported: id === "local/tee",
  } });
};

test("NEAR SDK discovery hides non-TEE and unknown models by default", async () => {
  const integration = createNearProvider({ policy: "trust-provider-and-host", catalogFetch });
  await integration.initializeCatalog();
  assert.deepEqual(integration.provider.getModels().map((model) => model.id), ["local/tee"]);
  assert.deepEqual(integration.getDiscoveredModels().map((model) => model.id), ["local/tee"]);
});

test("show-all exposes labeled discoveries without admitting non-TEE inference or weakening Approved policy", async () => {
  let opened = false;
  const integration = createNearProvider({ policy: "trust-provider-and-host", catalogFetch,
    openSdkTransport: async () => { opened = true; throw new Error("must not open for a non-TEE model"); },
  });
  await integration.initializeCatalog();
  integration.setModelVisibility("all");
  const models = integration.provider.getModels();
  assert.deepEqual(models.map((model) => model.id), ["local/tee", "external/zdr", "unknown/model"]);
  assert.match(models[1]!.name, /non-TEE; inference blocked/);
  assert.match(models[2]!.name, /TEE unknown; inference blocked/);
  assert.equal(integration.getDiscoveredModels()[1]?.selectable, false);
  for (const model of models.slice(1)) {
    const result = await integration.provider.streamSimple(model, normalizeContext({
      messages: [{ role: "user", content: "private prompt", timestamp: 1 }],
    }), { apiKey: "test-key" }).result();
    assert.equal(result.errorMessage, "TEE_MODEL_ATTESTATION_UNAVAILABLE");
  }
  assert.equal(opened, false);
  integration.setPolicy("public-builds");
  assert.deepEqual(integration.provider.getModels(), []);
  assert.equal(integration.getReport().modelVisibility, "all");
  assert.equal(integration.getReport().declaredTeeModels, 1);
});

test("offline snapshots retain capability; older unclassified models stay hidden", async () => {
  const online = createNearProvider({ policy: "trust-provider-and-host", catalogFetch });
  await online.initializeCatalog();
  const tee = online.provider.getModels()[0]!;
  const offline = createNearProvider({ policy: "trust-provider-and-host", catalogFetch: async () => { throw new Error("offline must not fetch"); } });
  await offline.provider.refreshModels!({
    allowNetwork: false, signal: new AbortController().signal,
    stored: { checkedAt: Date.now(), models: [tee, { ...tee, id: "legacy/model", teeCapability: undefined } as typeof tee] },
    publish: async (publication) => { publication.update?.(); return true; },
  });
  assert.deepEqual(offline.provider.getModels().map((model) => model.id), ["local/tee"]);
  offline.setModelVisibility("all");
  assert.equal(offline.getDiscoveredModels()[1]?.teeCapability, "unknown");
  assert.equal(offline.getDiscoveredModels()[1]?.selectable, false);
  assert.throws(() => offline.setModelVisibility("typo"), /TEE_MODEL_VISIBILITY_INVALID/);
  assert.equal(offline.getReport().modelVisibility, "all");
});

test("mismatched and malformed per-model claims cannot classify a model as TEE-capable", async () => {
  const integration = createNearProvider({ policy: "trust-provider-and-host", modelVisibility: "all", catalogFetch: async (input) => {
    if (String(input).endsWith("/models")) return Response.json({ data: rawModels });
    const id = decodeURIComponent(String(input).split("/model/")[1]!);
    return Response.json({ modelId: id === "local/tee" ? "other/model" : id,
      metadata: { providerType: "vllm", attestationSupported: id === "local/tee" ? true : "true" },
    });
  } });
  await integration.initializeCatalog();
  assert.equal(integration.getReport().declaredTeeModels, 0);
  assert.ok(integration.getDiscoveredModels().every((model) => model.teeCapability === "unknown" && !model.selectable));
  integration.setModelVisibility("tee");
  assert.deepEqual(integration.provider.getModels(), []);
});

test("a Chutes TEE declaration is distinct from an unavailable NEAR SDK protocol", async () => {
  let opened = false;
  const integration = createNearProvider({ policy: "trust-provider-and-host", catalogFetch: async (input) => {
    if (String(input).endsWith("/models")) return Response.json({ data: [{ ...rawModels[0], id: "chutes/tee" }] });
    return Response.json({ modelId: "chutes/tee", metadata: { providerType: "chutes", attestationSupported: true } });
  }, openSdkTransport: async () => { opened = true; throw new Error("Unsupported protocol must fail before SDK setup"); } });
  await integration.initializeCatalog();
  assert.equal(integration.getReport().declaredTeeModels, 1);
  assert.deepEqual(integration.provider.getModels(), [], "Default picker must not offer an unavailable transport.");
  assert.equal(integration.getDiscoveredModels()[0]?.teeCapability, "declared");
  assert.equal(integration.getDiscoveredModels()[0]?.selectable, false);
  integration.setModelVisibility("all");
  const model = integration.provider.getModels()[0]!;
  assert.match(model.name, /TEE declared; SDK transport unavailable/);
  assert.doesNotMatch(model.name, /non-TEE/);
  const result = await integration.provider.streamSimple(model, normalizeContext({
    messages: [{ role: "user", content: "synthetic prompt", timestamp: 1 }],
  }), { apiKey: "synthetic-key" }).result();
  assert.equal(result.errorMessage, "TEE_MODEL_TRANSPORT_UNAVAILABLE");
  assert.equal(opened, false);
  const offline = createNearProvider({ policy: "trust-provider-and-host", catalogFetch: async () => { throw new Error("No offline fetch"); } });
  await offline.provider.refreshModels!({
    allowNetwork: false, signal: new AbortController().signal,
    stored: { checkedAt: Date.now(), models: [model] },
    publish: async (publication) => { publication.update?.(); return true; },
  });
  assert.deepEqual(offline.provider.getModels(), []);
  assert.equal(offline.getDiscoveredModels()[0]?.teeCapability, "declared");
  assert.equal(offline.getDiscoveredModels()[0]?.sdkTransportAvailable, false);
  assert.equal(offline.getDiscoveredModels()[0]?.selectable, false);
});

test("an unrated replacement transport cannot inherit the gateway's potential H1 rating", async () => {
  let sent = false;
  const integration = createNearProvider({ policy: "trust-provider-and-host,host=current", catalogFetch,
    openSdkTransport: async () => ({ fetch: async () => { sent = true; return new Response('data: {"id":"c","choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n', { headers: { "content-type": "text/event-stream" } }); } }),
  });
  await integration.initializeCatalog();
  const result = await integration.provider.streamSimple(integration.provider.getModels()[0]!, normalizeContext({ messages: [{ role: "user", content: "synthetic", timestamp: 1 }] }), { apiKey: "synthetic-key" }).result();
  assert.equal(sent, false);
  assert.equal(result.stopReason, "error");
});
