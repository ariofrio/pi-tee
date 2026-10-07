import assert from "node:assert/strict";
import { test } from "node:test";
import { authenticateResponse } from "../packages/core/src/response.js";
import { limitResponseBody } from "../packages/core/src/transport.js";

const body = 'data: {"id":"completion-1","choices":[{"finish_reason":"stop","delta":{"content":"secret answer"}}]}\n\ndata: [DONE]\n\n';

test("signed response bytes are not readable while signature verification is pending", async () => {
  let finishVerification!: () => void;
  const signature = new Promise<void>((resolve) => { finishVerification = resolve; });
  const response = authenticateResponse(new Response(body, { headers: { "content-type": "text/event-stream" } }), {
    signal: new AbortController().signal, verify: async (id) => { assert.equal(id, "completion-1"); await signature; },
  });
  let readable = false;
  const text = response.text().then((value) => { readable = true; return value; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(readable, false);
  finishVerification();
  assert.equal(await text, body);
});

test("a forged signature releases no response bytes", async () => {
  const response = authenticateResponse(new Response(body, { headers: { "content-type": "text/event-stream" } }), {
    signal: new AbortController().signal,
    verify: async () => { throw new Error("forged signature"); },
  });
  await assert.rejects(response.body!.getReader().read(), /TEE_RESPONSE_REJECTED/);
});

test("a signed but incomplete or mixed-identity stream is rejected before signature lookup", async () => {
  for (const invalid of [body.replace("data: [DONE]\n\n", ""), body.replace("data: [DONE]", 'data: {"id":"completion-2","choices":[]}\n\ndata: [DONE]')]) {
    let verified = false;
    const response = authenticateResponse(new Response(invalid, { headers: { "content-type": "text/event-stream" } }), {
      signal: new AbortController().signal,
      verify: async () => { verified = true; },
    });
    await assert.rejects(response.text(), /TEE_RESPONSE_REJECTED/);
    assert.equal(verified, false);
  }
});

test("response memory limits and cancellation fail closed", async () => {
  const oversized = authenticateResponse(new Response(body), {
    signal: new AbortController().signal, maxBytes: 8, verify: async () => { throw new Error("unreachable"); },
  });
  await assert.rejects(oversized.text(), /TEE_RESPONSE_REJECTED/);
  const abort = new AbortController();
  const cancelled = authenticateResponse(new Response(body, { headers: { "content-type": "text/event-stream" } }), {
    signal: abort.signal, verify: () => new Promise<void>(() => undefined),
  });
  const text = cancelled.text();
  abort.abort();
  await assert.rejects(text, /TEE_RESPONSE_REJECTED/);
});

test("the network body is bounded before an SDK can retain ciphertext", async () => {
  let cancelled = false;
  let aborted = false;
  const upstream = new ReadableStream<Uint8Array>({
    pull(controller) { controller.enqueue(new Uint8Array(5)); },
    cancel() { cancelled = true; },
  });
  const response = limitResponseBody(new Response(upstream), {
    signal: new AbortController().signal, maxBytes: 8, cancel: () => { aborted = true; },
  });
  await assert.rejects(response.arrayBuffer(), /TEE_BODY_TOO_LARGE/);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(cancelled, true);
  assert.equal(aborted, true);
});

test("cancelling the authenticated body stops the upstream even without a transport callback", async () => {
  let cancelled = false;
  const upstream = new ReadableStream<Uint8Array>({
    pull() { return new Promise<void>(() => undefined); },
    cancel() { cancelled = true; },
  });
  const response = authenticateResponse(new Response(upstream), {
    signal: new AbortController().signal, verify: async () => undefined,
  });
  await response.body!.cancel();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(cancelled, true);
});
