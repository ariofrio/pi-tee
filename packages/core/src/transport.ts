import { TeeError } from "./policy.js";

export const MAX_REQUEST_BYTES = 16 * 1024 * 1024;
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
export const MAX_ENCRYPTED_RESPONSE_BYTES = 32 * 1024 * 1024;

export function limitResponseBody(response: Response, options: {
  signal: AbortSignal;
  maxBytes: number;
  cancel?(): void;
}): Response {
  if (!response.body) return response;
  let size = 0;
  const body = response.body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      size += chunk.byteLength;
      if (size > options.maxBytes) {
        options.cancel?.();
        throw new TeeError("TEE_BODY_TOO_LARGE");
      }
      controller.enqueue(chunk);
    },
  }), { signal: options.signal });
  return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
}

export async function withAbort<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    void operation.catch(() => undefined);
    throw signal.reason;
  }
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    operation.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

export async function readBoundedBody(body: ReadableStream<Uint8Array> | null, limit: number, signal: AbortSignal) {
  if (!body) throw new TeeError("TEE_RESPONSE_REJECTED");
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await withAbort(reader.read(), signal);
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > limit) throw new TeeError("TEE_BODY_TOO_LARGE");
      chunks.push(chunk.value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return bytes;
  } catch (error) {
    void reader.cancel(error).catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
}

const allowedFields = new Set([
  "model", "messages", "tools", "tool_choice", "parallel_tool_calls", "stream", "stream_options",
  "max_tokens", "max_completion_tokens", "temperature", "top_p", "stop", "frequency_penalty", "presence_penalty",
  "seed", "reasoning_effort", "thinking", "reasoning", "chat_template_kwargs", "enable_thinking",
  "store",
]);
const messageFields = new Set(["role", "content", "name", "tool_calls", "tool_call_id", "reasoning_content", "reasoning_details"]);

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateChat(body: unknown, model: string): asserts body is Record<string, unknown> {
  const fail = () => { throw new TeeError("TEE_REQUEST_REJECTED"); };
  if (!object(body) || body.model !== model || body.stream !== true || !Array.isArray(body.messages)) return fail();
  if (Object.keys(body).some((field) => !allowedFields.has(field))) return fail();
  if (body.store !== undefined && body.store !== false) return fail();
  if (body.stream_options !== undefined && (!object(body.stream_options) || Object.keys(body.stream_options).some((key) => key !== "include_usage"))) return fail();
  if (body.tools !== undefined) {
    if (!Array.isArray(body.tools)) return fail();
    for (const tool of body.tools) {
      if (!object(tool) || tool.type !== "function" || Object.keys(tool).some((key) => key !== "type" && key !== "function")) return fail();
      const fn = tool.function;
      if (!object(fn) || typeof fn.name !== "string" || Object.keys(fn).some((key) => !["name", "description", "parameters", "strict"].includes(key))) return fail();
      if (fn.parameters !== undefined && !object(fn.parameters)) return fail();
    }
  }
  if (body.tool_choice !== undefined && !["auto", "none", "required"].includes(String(body.tool_choice))) {
    if (!object(body.tool_choice) || body.tool_choice.type !== "function" || !object(body.tool_choice.function) || typeof body.tool_choice.function.name !== "string") return fail();
  }
  for (const message of body.messages) {
    if (!object(message) || Object.keys(message).some((field) => !messageFields.has(field))) return fail();
    if (!["system", "developer", "user", "assistant", "tool"].includes(String(message.role))) return fail();
    if (Array.isArray(message.content)) {
      for (const part of message.content) {
        if (!object(part)) return fail();
        if (part.type === "text" && typeof part.text === "string" && Object.keys(part).every((key) => key === "type" || key === "text")) continue;
        if (part.type === "image_url" && object(part.image_url) && typeof part.image_url.url === "string" &&
          /^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(part.image_url.url) &&
          Object.keys(part).every((key) => key === "type" || key === "image_url") &&
          Object.keys(part.image_url).every((key) => key === "url" || key === "detail")) continue;
        return fail();
      }
    } else if (message.content !== null && message.content !== undefined && typeof message.content !== "string") return fail();
  }
}

export function guardChatFetch(options: {
  fetch: typeof globalThis.fetch;
  endpoint: string;
  model: string;
  apiKey: string;
  signal: AbortSignal;
  onRejection(): void;
}): typeof globalThis.fetch {
  return async (input, init) => {
    let request: Request;
    let body: unknown;
    try {
      request = new Request(input, init);
      if (request.url !== options.endpoint || request.method !== "POST") throw new TeeError("TEE_REQUEST_REJECTED");
      const bytes = await readBoundedBody(request.body, MAX_REQUEST_BYTES, options.signal);
      body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      validateChat(body, options.model);
    } catch {
      options.onRejection();
      throw new TeeError("TEE_REQUEST_REJECTED");
    }
    const signal = AbortSignal.any([options.signal, request.signal]);
    signal.throwIfAborted();
    // Transport/auth headers are owned here; none of the caller's metadata headers are forwarded.
    return options.fetch(new Request(options.endpoint, {
      method: "POST", body: JSON.stringify(body), signal, redirect: "error",
      headers: { "content-type": "application/json", accept: "text/event-stream", authorization: `Bearer ${options.apiKey}` },
    }));
  };
}
