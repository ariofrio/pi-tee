import { Worker } from "node:worker_threads";
import {
  TeeError,
  isNetworkFailure,
  upstreamFailure,
  readBoundedBody,
  MAX_REQUEST_BYTES,
  MAX_ENCRYPTED_RESPONSE_BYTES,
  type RouteSecurity,
  type SdkTransport,
  type UpstreamCause,
} from "pi-tee-core";
import { guardPrivatemodeWire, PRIVATEMODE_BASE_URL } from "./wire.js";
import type { AdmittedManifest } from "./manifest.js";

export async function openPrivatemodeTransport(options: {
  apiKey: string;
  model: string;
  signal: AbortSignal;
  manifest: AdmittedManifest;
  networkFetch?: typeof globalThis.fetch;
}): Promise<{ security: RouteSecurity; transport: SdkTransport }> {
  options.signal.throwIfAborted();
  const started = Date.now();
  const worker = new Worker(
    new URL(
      import.meta.url.endsWith(".ts") ? "../dist/worker.js" : "./worker.js",
      import.meta.url,
    ),
    {
      workerData: {
        apiKey: options.apiKey,
        model: options.model,
        manifest: options.manifest.bytes,
      },
      resourceLimits: { maxOldGenerationSizeMb: 256 },
    },
  );
  const readers = new Map<
    number,
    { reader: ReadableStreamDefaultReader<Uint8Array>; bytes: number }
  >();
  let streamId = 0,
    ready = false,
    disposed = false,
    sent = false;
  let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
  let pendingChunk: number | undefined;
  // The SDK's own errors are discarded; only a fixed class of the last failed hop is kept.
  let upstream: UpstreamCause | undefined;
  let finishReady: (result: { observed: string[] }) => void;
  let rejectReady: (error: Error) => void;
  const admitted = new Promise<{ observed: string[] }>((resolve, reject) => {
    finishReady = resolve;
    rejectReady = reject;
  });
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    clearTimeout(timer);
    options.signal.removeEventListener("abort", abort);
    for (const { reader } of readers.values())
      void reader.cancel().catch(() => undefined);
    readers.clear();
    void worker.terminate();
  };
  const fail = () => {
    const code = ready ? "TEE_RESPONSE_REJECTED" : "TEE_ATTESTATION_REJECTED";
    const error = new TeeError(code, code, upstream);
    rejectReady(error);
    controller?.error(error);
    dispose();
  };
  const abort = () => fail();
  const timer = setTimeout(fail, 60000);
  options.signal.addEventListener("abort", abort, { once: true });
  if (options.signal.aborted) abort();
  worker.on("error", fail);
  worker.on("exit", () => {
    if (!disposed) fail();
  });
  const reply = (id: number, value?: unknown, error = false) => {
    if (!disposed) worker.postMessage({ kind: "rpc", id, value, error });
  };
  worker.on("message", (message: any) => {
    if (disposed) return;
    if (message.kind === "ready") {
      ready = true;
      clearTimeout(timer);
      finishReady({ observed: message.observed });
      return;
    }
    if (message.kind === "error") {
      fail();
      return;
    }
    if (message.kind === "done") {
      controller?.enqueue(new TextEncoder().encode("data: [DONE]\n\n"));
      controller?.close();
      return;
    }
    if (message.kind === "chunk") {
      if (
        !controller ||
        pendingChunk !== undefined ||
        typeof message.chunk !== "string" ||
        message.chunk.length > 4 * 1024 * 1024
      ) {
        fail();
        return;
      }
      controller.enqueue(
        new TextEncoder().encode(`data: ${message.chunk}\n\n`),
      );
      if ((controller.desiredSize ?? 0) > 0) reply(message.id);
      else pendingChunk = message.id;
      return;
    }
    void (async () => {
      try {
        options.signal.throwIfAborted();
        if (message.kind === "network") {
          const request = new Request(message.url, {
            method: message.method,
            headers: message.headers,
            body: message.body,
            signal: options.signal,
            redirect: "error",
          });
          guardPrivatemodeWire(
            request,
            options.model,
            options.apiKey,
            ready && sent,
          );
          const response = await (options.networkFetch ?? globalThis.fetch)(
            request,
            { redirect: "error", signal: options.signal },
          ).catch((error: unknown) => {
            if (isNetworkFailure(error)) upstream = { class: "connection failed" };
            throw error;
          });
          if (!response.ok)
            upstream = upstreamFailure(
              "TEE_RESPONSE_REJECTED",
              response.status,
              new URL(request.url).pathname === "/v1/chat/completions"
                ? "request"
                : "evidence",
            ).upstream;
          if (disposed) {
            await response.body?.cancel();
            return;
          }
          if (
            response.redirected ||
            (response.url && response.url !== request.url) ||
            !response.body
          )
            throw new TeeError("TEE_RESPONSE_REJECTED");
          const id = ++streamId;
          readers.set(id, { reader: response.body.getReader(), bytes: 0 });
          reply(message.id, {
            stream: id,
            status: response.status,
            headers: [...response.headers],
          });
        } else if (message.kind === "network-read") {
          const stream = readers.get(message.stream);
          if (!stream) throw new TeeError("TEE_RESPONSE_REJECTED");
          const value = await stream.reader.read();
          stream.bytes += value.value?.byteLength ?? 0;
          if (stream.bytes > MAX_ENCRYPTED_RESPONSE_BYTES)
            throw new TeeError("TEE_BODY_TOO_LARGE");
          if (value.done) readers.delete(message.stream);
          reply(message.id, value);
        } else if (message.kind === "network-cancel") {
          await readers.get(message.stream)?.reader.cancel();
          readers.delete(message.stream);
          reply(message.id);
        } else throw new TeeError("TEE_REQUEST_REJECTED");
      } catch {
        reply(message.id, undefined, true);
        fail();
      }
    })();
  });
  const result = await admitted;
  if (Date.now() >= started + 60000) {
    dispose();
    throw new TeeError("TEE_ATTESTATION_REJECTED");
  }
  const security: RouteSecurity = {
    route: "privatemode-mesh",
    provider: "Privatemode",
    cpuVerified: true,
    code: 2,
    host: 3,
    gpu: 3,
    egress: 3,
    observed: [
      `Exact manifest SHA-256 ${options.manifest.sha256}, source ${options.manifest.source}; change admission is controlled locally and recorded before bootstrap.`,
      "Client-fresh hardware evidence binds Coordinator state and mesh CA; serving-worker reports are neither client-fresh nor client-verified. No serving GPU evidence is authenticated by the client.",
      ...result.observed,
      "All manifest-admitted key recipients count, including secret service and all workloads sharing the deployment key. Their firmware, GPU coverage and handling are unverified below A1.",
    ],
  };
  return {
    security,
    transport: {
      baseUrl: PRIVATEMODE_BASE_URL,
      expiresAt: started + 60000,
      dispose,
      fetch: async (input, init) => {
        if (disposed || sent || Date.now() >= started + 60000)
          throw new TeeError("TEE_REQUEST_REJECTED");
        const request = new Request(input, init);
        if (
          request.url !== `${PRIVATEMODE_BASE_URL}/chat/completions` ||
          request.method !== "POST"
        )
          throw new TeeError("TEE_REQUEST_REJECTED");
        const bytes = await readBoundedBody(
          request.body,
          MAX_REQUEST_BYTES,
          options.signal,
        );
        options.signal.throwIfAborted();
        sent = true;
        const stream = new ReadableStream<Uint8Array>({
          start(value) {
            controller = value;
          },
          pull() {
            if (pendingChunk !== undefined) {
              const id = pendingChunk;
              pendingChunk = undefined;
              reply(id);
            }
          },
          cancel() {
            dispose();
          },
        });
        worker.postMessage({
          kind: "chat",
          body: new TextDecoder("utf-8", { fatal: true }).decode(bytes),
        });
        return new Response(stream, {
          headers: { "content-type": "text/event-stream" },
        });
      },
    },
  };
}
