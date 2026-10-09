import assert from "node:assert/strict";
import { test } from "node:test";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { createE2eeRequest, decryptE2eeStream } from "../packages/chutes/src/crypto.js";

import { acceptRequest, serverStream } from "./chutes-crypto-fixture.js";

test("Chutes E2EE encrypts the whole JSON payload and authenticates each streamed response", async () => {
  const server = ml_kem768.keygen();
  const payload = { messages: [{ role: "user", content: "private-prompt-π" }], tools: [{ name: "private-tool" }], reasoning: "private-reasoning" };
  const sealed = createE2eeRequest(Buffer.from(server.publicKey).toString("base64"), payload);
  for (const marker of ["private-prompt", "private-tool", "private-reasoning"]) assert.equal(Buffer.from(sealed.body).includes(Buffer.from(marker)), false);
  const opened = acceptRequest(sealed.body, server.secretKey);
  assert.deepEqual(opened.messages, payload.messages);
  assert.deepEqual(opened.tools, payload.tools);
  const chunk = 'data: {"id":"c1","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\n';
  const response = decryptE2eeStream(serverStream(opened.e2e_response_pk, [chunk]), sealed.responseSecret, AbortSignal.timeout(10000));
  assert.equal(await response.text(), chunk + "data: [DONE]\n\n");
});

test("Chutes rejects unauthenticated, replayed, corrupt and incomplete streaming responses", async () => {
  const server = ml_kem768.keygen();
  for (const fault of ["tag", "replay", "plain", "truncated"] as const) {
    const sealed = createE2eeRequest(Buffer.from(server.publicKey).toString("base64"), {});
    const opened = acceptRequest(sealed.body, server.secretKey);
    const chunk = 'data: {"id":"c1","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\n';
    await assert.rejects(decryptE2eeStream(serverStream(opened.e2e_response_pk, [chunk], fault), sealed.responseSecret, AbortSignal.timeout(10000)).text());
  }
});
