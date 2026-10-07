import { TeeError } from "./policy.js";
import { MAX_RESPONSE_BYTES, readBoundedBody, withAbort } from "./transport.js";

function completionId(bytes: Uint8Array, contentType: string | null): string {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (!contentType?.toLowerCase().startsWith("text/event-stream")) {
    const value = JSON.parse(text) as { id?: unknown; choices?: { finish_reason?: unknown }[] };
    if (typeof value.id !== "string" || !value.id || !value.choices?.some((choice) => typeof choice.finish_reason === "string")) {
      throw new TeeError("TEE_RESPONSE_REJECTED");
    }
    return value.id;
  }
  let id: string | undefined;
  let done = false;
  let finished = false;
  for (const record of text.replace(/\r\n?/g, "\n").split("\n\n")) {
    const data = record.split("\n").filter((line) => line.startsWith("data:")).map((line) => line.slice(5).replace(/^ /, "")).join("\n");
    if (!data) continue;
    if (done) throw new TeeError("TEE_RESPONSE_REJECTED");
    if (data === "[DONE]") { done = true; continue; }
    const chunk = JSON.parse(data) as { id?: unknown; choices?: { index?: unknown; finish_reason?: unknown }[] };
    if (typeof chunk.id !== "string" || !chunk.id || (id !== undefined && id !== chunk.id) || !Array.isArray(chunk.choices)) {
      throw new TeeError("TEE_RESPONSE_REJECTED");
    }
    id = chunk.id;
    for (const choice of chunk.choices) {
      if (choice.index !== undefined && choice.index !== 0) throw new TeeError("TEE_RESPONSE_REJECTED");
      if (typeof choice.finish_reason === "string") finished = true;
    }
  }
  if (!id || !done || !finished) throw new TeeError("TEE_RESPONSE_REJECTED");
  return id;
}

export function authenticateResponse(response: Response, options: {
  signal: AbortSignal;
  verify(completionId: string): Promise<void>;
  maxBytes?: number;
  cancel?(): void;
}): Response {
  if (!response.ok) return response;
  const cancellation = new AbortController();
  const signal = AbortSignal.any([options.signal, cancellation.signal]);
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  headers.delete("content-encoding");
  const body = new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        const bytes = await readBoundedBody(response.body, options.maxBytes ?? MAX_RESPONSE_BYTES, signal);
        const id = completionId(bytes, headers.get("content-type"));
        signal.throwIfAborted();
        await withAbort(options.verify(id), signal);
        signal.throwIfAborted();
        controller.enqueue(bytes);
        controller.close();
      } catch {
        options.cancel?.();
        controller.error(new TeeError("TEE_RESPONSE_REJECTED"));
      }
    },
    cancel() { cancellation.abort(); options.cancel?.(); },
  });
  return new Response(body, { status: response.status, statusText: response.statusText, headers });
}
