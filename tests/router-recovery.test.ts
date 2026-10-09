import assert from "node:assert/strict";
import { test } from "node:test";
import { KeyConfigMismatchError } from "ehbp";
import { SecureClient } from "tinfoil";
import { normalizeContext } from "@earendil-works/pi-ai/compat";
import { createTinfoilProvider } from "../packages/tinfoil/src/index.js";
import { formatProviderReport } from "../packages/core/src/status.js";

// Inject only the external SDK's ready transport. Its actual fetch getter,
// reset/re-attestation and rotation recovery run through the native provider.
for (const outcome of ["rotated", "rotated-twice", "other-error"] as const) {
  test(`router preserves exactly the SDK's one rotation resend (${outcome})`, async () => {
    const ready = SecureClient.prototype.ready;
    const attempts: { url: string; auth: string | null; body: string }[] = [];
    let appraisals = 0;
    SecureClient.prototype.ready = async function () {
      const client = this as unknown as { _transport: { fetch: typeof globalThis.fetch } | null };
      if (client._transport) return;
      appraisals++;
      client._transport = { fetch: async (input, init) => {
        const request = new Request(input, init);
        attempts.push({ url: request.url, auth: request.headers.get("authorization"), body: await request.text() });
        if (outcome === "other-error") throw new Error("synthetic ambiguous transport error");
        if (attempts.length === 1 || outcome === "rotated-twice") throw new KeyConfigMismatchError();
        return new Response('data: {"id":"c1","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n', { headers: { "content-type": "text/event-stream" } });
      } };
    };
    try {
      const integration = createTinfoilProvider({ policy: "trust-provider-and-host", route: "router",
        catalogFetch: async () => Response.json({ data: [{ id: "gpt-oss-120b", name: "Synthetic router", type: "chat", tool_calling: true, endpoints: ["/v1/chat/completions"], context_window: 8192, max_tokens: 1024, pricing: { inputTokenPricePer1M: 1, outputTokenPricePer1M: 1 } }] }),
      });
      await integration.initializeCatalog();
      const model = integration.provider.getModels()[0]!;
      const result = await integration.provider.streamSimple(model, normalizeContext({ messages: [{ role: "user", content: "synthetic rotation prompt", timestamp: 1 }] }), { apiKey: "synthetic-key", maxRetries: 10 }).result();
      assert.equal(attempts.length, outcome === "other-error" ? 1 : 2);
      assert.equal(appraisals, outcome === "other-error" ? 1 : 2);
      assert.equal(result.stopReason, outcome === "rotated" ? "stop" : "error");
      if (outcome !== "rotated") assert.equal(result.errorMessage, "TEE_REQUEST_FAILED");
      if (attempts.length === 2) assert.deepEqual(attempts[1], attempts[0]);
      assert.equal(attempts[0]!.url, "https://inference.tinfoil.sh/v1/chat/completions");
      assert.equal(attempts[0]!.auth, "Bearer synthetic-key");
      assert.equal(JSON.parse(attempts[0]!.body).messages.at(-1).content, "synthetic rotation prompt");
      assert.match(formatProviderReport(integration.getReport()), /re-attests and resends once only on EHBP key-configuration mismatch/);
    } finally { SecureClient.prototype.ready = ready; }
  });
}
