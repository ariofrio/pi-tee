import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeContext } from "@earendil-works/pi-ai/compat";
import { formatProviderReport } from "pi-tee-core";
import { createNearProvider } from "../packages/nearai/src/index.js";

const glm = "z-ai/glm-5.3-flash", qwen = "Qwen/Qwen3.6-35B-A3B-FP8";
const raw = (id: string, tools = true) => ({ id, name: id, context_length: 8192, supported_features: tools ? ["tools"] : [], output_modalities: ["text"] });
const context = normalizeContext({ messages: [{ role: "user", content: "synthetic prompt", timestamp: 1 }] });
function discovery(models = [raw(glm), raw(qwen)], endpoints = [
  { domain: "glm-5-3-flash.completions.near.ai", models: [glm] },
  { domain: "qwen3-6-35b.completions.near.ai", models: [qwen] },
]): typeof globalThis.fetch {
  return async input => {
    const url = String(input);
    if (url.endsWith("/models")) return Response.json({ data: models });
    if (url.endsWith("/model/list")) return Response.json({ models: models.map(m => ({ modelId: m.id, metadata: { providerType: "vllm", attestationSupported: true, supportedFeatures: m.supported_features } })), total: models.length, offset: 0, limit: 100 });
    if (url === "https://completions.near.ai/endpoints") return Response.json({ endpoints });
    return Response.json({ modelId: decodeURIComponent(url.split("/model/")[1]!), metadata: { providerType: "vllm", attestationSupported: true } });
  };
}

test("NEAR direct offers catalog tool models with registry endpoints, excluding orphan and no-tool entries", async () => {
  const noTools = "Qwen/Qwen3-VL-30B-A3B-Instruct";
  const integration = createNearProvider({ route: "direct", policy: "trust-provider-and-host", catalogFetch: discovery(
    [raw(glm), raw(qwen), raw(noTools, false), raw("no/endpoint")], [
      { domain: "glm-5-3-flash.completions.near.ai", models: [glm] },
      { domain: "qwen3-6-35b.completions.near.ai", models: [qwen] },
      { domain: "orphan.completions.near.ai", models: ["absent/model"] },
      { domain: "vl.completions.near.ai", models: [noTools] },
    ]) });
  await integration.initializeCatalog();
  assert.deepEqual(integration.provider.getModels().map(m => m.id), [glm, qwen]);
});

test("hostile registry hostnames cannot become direct candidates", async () => {
  for (const domain of ["evil.example", "https://qwen.completions.near.ai", "qwen.completions.near.ai:443", "x.qwen.completions.near.ai", "QWEN.completions.near.ai", "qwen.completions.near.ai@evil.example", "qwen.completions.near.ai/path", "qwen.completions.near.ai\n"]) {
    const integration = createNearProvider({ route: "direct", policy: "trust-provider-and-host", catalogFetch: discovery([raw(qwen)], [{ domain, models: [qwen] }]) });
    await integration.initializeCatalog();
    assert.deepEqual(integration.provider.getModels(), [], JSON.stringify(domain));
  }
});

// External quote-verifier and HTTP seams: real SDK binding/deployment checks,
// real provider policy and native message conversion; no genuine quote signature.
async function evidenceSeams(host = 2, unavailable?: string) {
  const { readFile } = await import("node:fs/promises");
  const { createHash } = await import("node:crypto");
  const fixture = JSON.parse(await readFile("tests/fixtures/near-glm-direct-attestation.json", "utf8"));
  const requested: string[] = [], sends: string[] = [], closed: string[] = [];
  const hash = (algo: string, data: Uint8Array | string) => createHash(algo).update(data).digest();
  const directSeams = (target: { hostname: string; model: string }) => {
    let reportData = new Uint8Array(64);
    return {
      channel: {
        async request(request: Request) {
          requested.push(new URL(request.url).hostname);
          if (target.hostname === unavailable) throw Error("unreachable");
          const nonce = new URL(request.url).searchParams.get("nonce")!;
          reportData = Buffer.concat([hash("sha256", Buffer.concat([Buffer.from(fixture.signing_address, "hex"), Buffer.from(fixture.tls_cert_fingerprint, "hex")])), Buffer.from(nonce, "hex")]);
          const body = { model_name: target.model, signing_algo: "ed25519", signing_address: fixture.signing_address, signing_public_key: fixture.signing_public_key,
            request_nonce: nonce, intel_quote: "00", tls_cert_fingerprint: fixture.tls_cert_fingerprint,
            info: { tcb_info: { app_compose: "{}" } }, event_log: [{ imr: 3, event_type: 0, digest: "00".repeat(48), event: "", event_payload: "" }] };
          return { response: Response.json({ ...body, all_attestations: [body], ohttp_attestation: fixture.ohttp_attestation }), peerSpkiFingerprint: fixture.tls_cert_fingerprint };
        },
        fetch: async () => { sends.push(target.hostname); throw Error("synthetic inference boundary"); },
        approve() {}, close() { closed.push(target.hostname); },
      },
      cpu: {
        collateral: async () => ({ tcb_info: '{"tcbEvaluationDataNumber":20}', qe_identity: '{"tcbEvaluationDataNumber":20}' }) as any,
        verify: () => ({ status: "UpToDate", advisory_ids: [], report: { asTd10: () => ({
          teeTcbSvn: Uint8Array.from([host === 1 ? 3 : 2, 1, 2, ...Array(13).fill(0)]),
          tdAttributes: new Uint8Array(8), reportData, mrConfigId: Buffer.concat([Buffer.from([1]), hash("sha256", "{}"), Buffer.alloc(15)]), rtMr3: hash("sha384", Buffer.alloc(96)),
        }) } }) as any,
      },
    };
  };
  return { directSeams, requested, sends, closed };
}

test("a below-floor direct instance is H2, rejected before prompt by host=current and admitted by outdated-firmware", async () => {
  for (const current of [true, false]) {
    const seam = await evidenceSeams();
    const integration = createNearProvider({ route: "direct", policy: `trust-provider-and-host,host=${current ? "current" : "outdated-firmware"}`, catalogFetch: discovery([raw(qwen)]), ...seam });
    await integration.initializeCatalog();
    await integration.provider.streamSimple(integration.provider.getModels()[0]!, context, { apiKey: "synthetic-key", timeoutMs: 10000 }).result();
    const decision = integration.getReport().routeDecisions?.find(r => r.route === "near-direct");
    assert.equal(decision?.security?.host, 2);
    assert.equal(decision?.accepted, !current);
    assert.equal(seam.sends.length, current ? 0 : 1);
    const status = formatProviderReport(integration.getReport());
    assert.match(status, /near-direct: A3 H2 G3 X3/);
    assert.match(status, /below pi-tee's floors/);
    if (current) assert.match(status, /host level 2 exceeds host=current/);
  }
});

test("an unreachable registry endpoint is skipped, reported in status, and receives no prompt", async () => {
  const dead = "dead.completions.near.ai", live = "qwen3-6-35b.completions.near.ai";
  for (const hosts of [[dead, live], [dead]]) {
    const seam = await evidenceSeams(1, dead);
    const integration = createNearProvider({ route: "direct", policy: "trust-provider-and-host,host=current", catalogFetch: discovery([raw(qwen)], hosts.map(domain => ({ domain, models: [qwen] }))), ...seam });
    await integration.initializeCatalog();
    await integration.provider.streamSimple(integration.provider.getModels()[0]!, context, { apiKey: "synthetic-key" }).result();
    assert.deepEqual(seam.requested, hosts);
    assert.deepEqual(seam.sends, hosts.length === 2 ? [live] : []);
    assert.ok(seam.closed.includes(dead));
    const status = formatProviderReport(integration.getReport());
    assert.match(status, /dead\.completions\.near\.ai.*skipped.*unreachable/);
    if (hosts.length === 2) assert.match(status, /near-direct: A3 H1 G3 X3/);
  }
});

test("discovery requires matching tool and attestation declarations in both catalog views", async () => {
  for (const detail of [
    { modelId: "other/model", metadata: { attestationSupported: true, providerType: "vllm", supportedFeatures: ["tools"] } },
    { modelId: qwen, metadata: { attestationSupported: false, providerType: "vllm", supportedFeatures: ["tools"] } },
    { modelId: qwen, metadata: { attestationSupported: true, providerType: "vllm", supportedFeatures: [] } },
  ]) {
    const base = discovery([raw(qwen)]);
    const integration = createNearProvider({ route: "direct", policy: "trust-provider-and-host", catalogFetch: async (input, init) => String(input).endsWith("/model/list") ? Response.json({ models: [detail], offset: 0, total: 1 }) : base(input, init) });
    await integration.initializeCatalog();
    assert.deepEqual(integration.provider.getModels(), []);
  }
});

test("direct evidence for a different model cannot inherit a catalog/registry match", async () => {
  const seam = await evidenceSeams(1);
  const real = seam.directSeams;
  seam.directSeams = target => real({ ...target, model: "other/model" });
  const integration = createNearProvider({ route: "direct", policy: "trust-provider-and-host", catalogFetch: discovery([raw(qwen)]), ...seam });
  await integration.initializeCatalog();
  await integration.provider.streamSimple(integration.provider.getModels()[0]!, context, { apiKey: "synthetic-key" }).result();
  assert.deepEqual(seam.sends, []);
  assert.equal(integration.getReport().routeDecisions?.[0]?.accepted, false);
});

test("a catalog provider label does not exclude a declared tool model with a direct endpoint", async () => {
  const base = discovery([raw(qwen)]);
  const integration = createNearProvider({ route: "direct", policy: "trust-provider-and-host", catalogFetch: async (input, init) => {
    const response = await base(input, init);
    if (!String(input).includes("/model/")) return response;
    const value = await response.json();
    if (value.models) for (const model of value.models) model.metadata.providerType = "chutes";
    else value.metadata.providerType = "chutes";
    return Response.json(value);
  } });
  await integration.initializeCatalog();
  assert.deepEqual(integration.provider.getModels().map(m => m.id), [qwen]);
});
