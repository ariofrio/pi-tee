import { hkdfSync, randomBytes } from "node:crypto";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { gzipSync } from "node:zlib";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { limitResponseBody, MAX_ENCRYPTED_RESPONSE_BYTES, MAX_RESPONSE_BYTES, TeeError, withAbort } from "pi-tee-core";
import { base64 } from "./evidence.js";

function key(secret: Uint8Array, ct: Uint8Array, info: string) {
  return Buffer.from(hkdfSync("sha256", secret, ct.subarray(0, 16), info, 32));
}

export function createE2eeRequest(publicKey: string, payload: Record<string, unknown>) {
  const response = ml_kem768.keygen();
  const exchange = ml_kem768.encapsulate(base64(publicKey, 1184));
  const k = key(exchange.sharedSecret, exchange.cipherText, "e2e-req-v1");
  exchange.sharedSecret.fill(0);
  const nonce = randomBytes(12);
  const compressed = gzipSync(JSON.stringify({ ...payload, e2e_response_pk: Buffer.from(response.publicKey).toString("base64") }));
  const body = Buffer.concat([exchange.cipherText, nonce, chacha20poly1305(k, nonce).encrypt(compressed)]);
  k.fill(0);
  return { body, responseSecret: response.secretKey };
}

export function decryptE2eeStream(response: Response, secret: Uint8Array, signal: AbortSignal): Response {
  if (!response.ok || !response.body || !response.headers.get("content-type")?.startsWith("text/event-stream")) throw new TeeError("TEE_RESPONSE_REJECTED");
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const encoder = new TextEncoder();
  let pending = "";
  let streamKey: Buffer | undefined;
  let finished = false;
  let done = false;
  const nonces = new Set<string>();
  const reader = response.body.getReader();
  let inputBytes = 0;
  const fail = () => { throw new TeeError("TEE_RESPONSE_REJECTED"); };
  const cleanup = () => { secret.fill(0); streamKey?.fill(0); };
  const abort = () => { cleanup(); void reader.cancel().catch(() => undefined); };
  signal.addEventListener("abort", abort, { once: true });
  const transform = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      try {
        signal.throwIfAborted();
        pending += decoder.decode(chunk, { stream: true });
        if (pending.length > 2 * 1024 * 1024) fail();
        let newline: number;
        while ((newline = pending.indexOf("\n")) !== -1) {
          const line = pending.slice(0, newline).replace(/\r$/, "");
          pending = pending.slice(newline + 1);
          if (!line || line.startsWith(":")) continue;
          if (!line.startsWith("data: ") || done) fail();
          const raw = line.slice(6);
          if (raw === "[DONE]") {
            if (!streamKey || !finished) fail();
            done = true;
            controller.enqueue(encoder.encode("data: [DONE]\n\n"));
            continue;
          }
          const event = JSON.parse(raw);
          if (!event || typeof event !== "object" || Array.isArray(event)) fail();
          if (Object.keys(event).length === 1 && event.e2e_init) {
            if (streamKey) fail();
            const ct = base64(event.e2e_init, 1088);
            const shared = ml_kem768.decapsulate(ct, secret);
            streamKey = key(shared, ct, "e2e-stream-v1");
            shared.fill(0);
            secret.fill(0);
          } else if (Object.keys(event).length === 1 && event.e2e) {
            if (!streamKey) fail();
            const bytes = base64(event.e2e);
            if (bytes.length < 28) fail();
            const nonce = bytes.subarray(0, 12).toString("hex");
            if (nonces.has(nonce) || nonces.size >= 100000) fail();
            nonces.add(nonce);
            const text = new TextDecoder("utf-8", { fatal: true }).decode(chacha20poly1305(streamKey!, bytes.subarray(0, 12)).decrypt(bytes.subarray(12)));
            // The protocol encrypts complete SSE records, including the final choice.
            for (const data of text.split(/\r?\n/).filter(line => line.startsWith("data: "))) {
              if (data.slice(6) === "[DONE]") { finished = true; continue; }
              const item = JSON.parse(data.slice(6));
              if (item.error) fail();
              if (item.choices?.some((choice: any) => choice.index === 0 && typeof choice.finish_reason === "string")) finished = true;
            }
            controller.enqueue(encoder.encode(text.endsWith("\n\n") ? text : text.trimEnd() + "\n\n"));
          } else if (Object.keys(event).every(field => ["usage", "model"].includes(field)) && event.usage && streamKey) {
            // Billing counters are provider metadata, not enclave-authenticated content.
            const usage = event.usage;
            if (Object.keys(usage).some(field => !["prompt_tokens", "completion_tokens", "total_tokens"].includes(field)) ||
              Object.values(usage).some(value => !Number.isSafeInteger(value) || Number(value) < 0)) fail();
            controller.enqueue(encoder.encode(`data: ${JSON.stringify({ choices: [], usage })}\n\n`));
          } else fail();
        }
      } catch {
        abort();
        signal.removeEventListener("abort", abort);
        throw new TeeError("TEE_RESPONSE_REJECTED");
      }
    },
    flush() {
      cleanup();
      signal.removeEventListener("abort", abort);
      decoder.decode();
      if (!done || pending.trim()) fail();
    },
  });
  const source = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const item = await withAbort(reader.read(), signal);
        if (item.done) { controller.close(); return; }
        inputBytes += item.value.length;
        if (inputBytes > MAX_ENCRYPTED_RESPONSE_BYTES) throw new TeeError("TEE_BODY_TOO_LARGE");
        controller.enqueue(item.value);
      } catch (error) { abort(); controller.error(error); }
    },
    cancel() { abort(); signal.removeEventListener("abort", abort); },
  });
  const output = new Response(source.pipeThrough(transform, { signal }), { headers: { "content-type": "text/event-stream" } });
  return limitResponseBody(output, { signal, maxBytes: MAX_RESPONSE_BYTES, cancel: abort });
}
