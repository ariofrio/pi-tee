// Research probe only; not an Approved transport or a registered Pi provider.
// Evidence-only by default. --infer sends one fixed, capped synthetic prompt.
import assert from "node:assert/strict";
import { SecureClient } from "tinfoil";
import { randomBytes } from "node:crypto";
const infer = process.argv.includes("--infer");
const host = "gemma4-31b-inf6-3.tinfoil.containers.tinfoil.dev";
const repo = "tinfoilsh/confidential-gemma4-31b";
const result = {
  host,
  repo,
  model: "gemma4-31b",
  checkedAt: new Date().toISOString(),
  mode: infer ? "synthetic-inference" : "evidence-only",
  logicalChatRequests: 0,
};
const fetch0 = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const request = new Request(input, init);
  return fetch0(
    new Request(request, {
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(45000)]),
    }),
  );
};
try {
  if (infer) assert.ok(process.env.TINFOIL_API_KEY, "KEY_REQUIRED");
  const client = new SecureClient({
    enclaveURL: `https://${host}`,
    configRepo: repo,
    transport: "ehbp",
    userCacheSecret: randomBytes(32).toString("hex"),
  });
  await client.ready();
  const doc = client.getVerificationDocument();
  assert.equal(doc.securityVerified, true);
  assert.equal(doc.enclaveHost, host);
  Object.assign(result, {
    sdkVerified: true,
    verifiedPlatform: doc.enclaveMeasurement.measurement.type,
    releaseTag: doc.releaseTag,
    releaseDigest: doc.releaseDigest,
  });
  if (!infer) {
    const response = await client.fetch(
      new URL("models", client.getBaseURL()),
      { signal: AbortSignal.timeout(30000) },
    );
    result.status = response.status;
    assert.equal(response.status, 200, "MODEL_METADATA_STATUS");
    const value = await response.json();
    result.modelMetadataMatches = (value.data ?? []).some(
      (x) => x.id === "gemma4-31b",
    );
  } else {
    const body = JSON.stringify({
      model: "gemma4-31b",
      messages: [
        { role: "user", content: "Reply with exactly DIRECT_ACCESS_OK." },
      ],
      stream: true,
      stream_options: { include_usage: true },
      max_tokens: 128,
      chat_template_kwargs: { enable_thinking: false },
    });
    result.logicalChatRequests++;
    const response = await client.fetch(
      new URL("chat/completions", client.getBaseURL()),
      {
        method: "POST",
        signal: AbortSignal.timeout(60000),
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${process.env.TINFOIL_API_KEY}`,
        },
        body,
      },
    );
    result.status = response.status;
    assert.equal(response.status, 200, "INFERENCE_STATUS");
    const text = await response.text();
    assert.ok(text.length < 1024 * 1024);
    let content = "";
    let usage = false;
    let finish;
    for (const line of text.split("\n")) {
      if (!line.startsWith("data: ") || line === "data: [DONE]") continue;
      const v = JSON.parse(line.slice(6));
      for (const c of v.choices ?? []) {
        if (typeof c.delta?.content === "string") content += c.delta.content;
        if (c.finish_reason) finish = c.finish_reason;
      }
      usage ||= (v.usage?.total_tokens ?? 0) > 0;
    }
    Object.assign(result, {
      syntheticMarker: content.includes("DIRECT_ACCESS_OK"),
      usageReturned: usage,
      finishReason: finish,
    });
  }
} catch (error) {
  result.errorClass = error?.constructor?.name;
  result.failure =
    error instanceof assert.AssertionError
      ? error.message.split("\n")[0]
      : "unclassified";
}
console.log(JSON.stringify(result));
if (
  result.failure ||
  (!infer && result.modelMetadataMatches !== true) ||
  (infer && (!result.syntheticMarker || !result.usageReturned))
)
  process.exitCode = 1;
