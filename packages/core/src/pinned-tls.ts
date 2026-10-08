import { createHash, X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import { connect, type TLSSocket } from "node:tls";
import { TeeError } from "./policy.js";
import { MAX_REQUEST_BYTES, readBoundedBody } from "./transport.js";

const MAX_RESPONSE_HEADER_BYTES = 64 * 1024;
const FORBIDDEN_REQUEST_HEADERS = new Set(["host", "connection", "content-length", "transfer-encoding", "keep-alive", "upgrade", "te", "trailer", "expect"]);

/** Credentials are transmitted only after the exact socket presents the attested SPKI. */
export function pinnedTlsFetch(endpoint: string, fingerprint: string, expiresAt?: number): typeof globalThis.fetch {
  const target = new URL(endpoint);
  if (target.protocol !== "https:" || target.username || target.password || target.search || target.hash ||
      !/^[a-f0-9]{64}$/.test(fingerprint) ||
      (expiresAt !== undefined && (!Number.isSafeInteger(expiresAt) || expiresAt <= 0))) throw new TeeError("TEE_REQUEST_REJECTED");
  return async (input, init) => {
    const request = new Request(input, init);
    if (request.url !== endpoint || request.method !== "POST") throw new TeeError("TEE_REQUEST_REJECTED");
    const signal = request.signal;
    const body = await readBoundedBody(request.body, MAX_REQUEST_BYTES, signal);
    signal.throwIfAborted();
    const socket = connect({
      host: target.hostname, port: Number(target.port || 443),
      servername: isIP(target.hostname) ? undefined : target.hostname,
      // Attested SPKI replaces WebPKI authorization. No HTTP is written before checking it.
      rejectUnauthorized: false, minVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"],
    });
    const abort = () => socket.destroy(new TeeError("TEE_CONNECTION_FAILED"));
    signal.addEventListener("abort", abort, { once: true });
    const connectionTimeout = setTimeout(() => socket.destroy(new TeeError("TEE_CONNECTION_FAILED")), 10000);
    try {
      await new Promise<void>((resolve, reject) => {
        socket.once("error", reject);
        socket.once("close", () => reject(new TeeError("TEE_CONNECTION_FAILED")));
        socket.once("secureConnect", () => {
          try {
            const certificate = socket.getPeerCertificate().raw;
            if (!certificate) throw new TeeError("TEE_TLS_KEY_REJECTED");
            const spki = new X509Certificate(certificate).publicKey.export({ type: "spki", format: "der" });
            if (createHash("sha256").update(spki).digest("hex") !== fingerprint) throw new TeeError("TEE_TLS_KEY_REJECTED");
            resolve();
          } catch { reject(new TeeError("TEE_TLS_KEY_REJECTED")); }
        });
      });
      clearTimeout(connectionTimeout);
      signal.throwIfAborted();
      if (expiresAt !== undefined && Date.now() >= expiresAt) throw new TeeError("TEE_PUBLIC_SESSION_REJECTED");
      // One request per connection: no keep-alive, pipelining or reuse.
      const lines = [`POST ${target.pathname} HTTP/1.1`, `Host: ${target.host}`];
      for (const [name, value] of request.headers) {
        if (FORBIDDEN_REQUEST_HEADERS.has(name) || /[\r\n]/.test(name) || /[\r\n]/.test(value)) continue;
        lines.push(`${name}: ${value}`);
      }
      lines.push(`Content-Length: ${body.length}`, "Connection: close", "", "");
      socket.write(Buffer.concat([Buffer.from(lines.join("\r\n"), "latin1"), Buffer.from(body)]));
      return await readResponse(socket, signal);
    } catch (error) {
      clearTimeout(connectionTimeout);
      signal.removeEventListener("abort", abort);
      socket.destroy();
      if (signal.aborted) throw signal.reason ?? error;
      throw error instanceof TeeError ? error : new TeeError("TEE_CONNECTION_FAILED");
    }
  };
}

// Minimal HTTP/1.1 response reader for one Connection: close exchange. Bun's
// https.Agent cannot adopt an externally verified socket, so the verified
// socket carries the request directly.
function readResponse(socket: TLSSocket, signal: AbortSignal): Promise<Response> {
  return new Promise<Response>((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    let settled = false;
    const fail = (error: unknown) => { if (!settled) { settled = true; reject(error); } socket.destroy(); };
    const onData = (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      for (;;) {
        const end = buffered.indexOf("\r\n\r\n");
        if (end < 0) {
          if (buffered.length > MAX_RESPONSE_HEADER_BYTES) fail(new TeeError("TEE_RESPONSE_REJECTED"));
          return;
        }
        const head = buffered.subarray(0, end).toString("latin1").split("\r\n");
        const rest = buffered.subarray(end + 4);
        const status = /^HTTP\/1\.[01] ([1-5][0-9]{2})(?: .*)?$/.exec(head[0] ?? "");
        if (!status) return fail(new TeeError("TEE_RESPONSE_REJECTED"));
        const code = Number(status[1]);
        if (code >= 100 && code < 200 && code !== 101) { buffered = rest; continue; }
        if (code === 101) return fail(new TeeError("TEE_RESPONSE_REJECTED"));
        const headers = new Headers();
        for (const line of head.slice(1)) {
          const colon = line.indexOf(":");
          if (colon <= 0) return fail(new TeeError("TEE_RESPONSE_REJECTED"));
          headers.append(line.slice(0, colon).trim(), line.slice(colon + 1).trim());
        }
        socket.off("data", onData);
        let stream: ReadableStream<Uint8Array> | null = null;
        try { if (![204, 205, 304].includes(code)) stream = bodyStream(socket, headers, rest, signal); } catch (error) { return fail(error); }
        settled = true;
        resolve(new Response(stream, { status: code, headers }));
        return;
      }
    };
    socket.on("data", onData);
    socket.once("error", fail);
    socket.once("close", () => fail(new TeeError("TEE_CONNECTION_FAILED")));
  });
}

function bodyStream(socket: TLSSocket, headers: Headers, initial: Buffer, signal: AbortSignal): ReadableStream<Uint8Array> {
  const encoding = headers.get("transfer-encoding")?.toLowerCase();
  const declared = headers.get("content-length");
  if (encoding !== undefined && encoding !== null && encoding !== "chunked") { socket.destroy(); throw new TeeError("TEE_RESPONSE_REJECTED"); }
  if (encoding !== "chunked" && declared !== null && !/^[0-9]{1,15}$/.test(declared)) { socket.destroy(); throw new TeeError("TEE_RESPONSE_REJECTED"); }
  let remaining = encoding === "chunked" ? 0 : declared === null ? Infinity : Number(declared);
  let pending = initial;
  let chunkLeft = -1; // chunked: bytes left in the current chunk; -1 awaiting a size line, -2 awaiting CRLF
  let done = false;
  const finish = () => { done = true; socket.destroy(); };
  return new ReadableStream<Uint8Array>({
    start(controller) {
      const abort = () => { if (!done) { done = true; controller.error(new TeeError("TEE_CONNECTION_FAILED")); } socket.destroy(); };
      signal.addEventListener("abort", abort, { once: true });
      const drain = () => {
        if (encoding !== "chunked") {
          if (pending.length) {
            const take = pending.subarray(0, Math.min(pending.length, remaining));
            remaining -= take.length; pending = Buffer.alloc(0);
            if (take.length) controller.enqueue(new Uint8Array(take));
          }
          if (remaining === 0) { finish(); signal.removeEventListener("abort", abort); controller.close(); }
          return;
        }
        for (;;) {
          if (chunkLeft === -1) {
            const line = pending.indexOf("\r\n");
            if (line < 0) { if (pending.length > 1024) throw new TeeError("TEE_RESPONSE_REJECTED"); return; }
            const size = /^([0-9a-fA-F]{1,8})(?:;.*)?$/.exec(pending.subarray(0, line).toString("latin1"));
            if (!size) throw new TeeError("TEE_RESPONSE_REJECTED");
            pending = pending.subarray(line + 2);
            chunkLeft = Number.parseInt(size[1]!, 16);
            if (chunkLeft === 0) { finish(); signal.removeEventListener("abort", abort); controller.close(); return; }
          } else if (chunkLeft === -2) {
            if (pending.length < 2) return;
            if (pending[0] !== 13 || pending[1] !== 10) throw new TeeError("TEE_RESPONSE_REJECTED");
            pending = pending.subarray(2); chunkLeft = -1;
          } else {
            if (!pending.length) return;
            const take = pending.subarray(0, Math.min(pending.length, chunkLeft));
            pending = pending.subarray(take.length); chunkLeft -= take.length;
            controller.enqueue(new Uint8Array(take));
            if (chunkLeft === 0) chunkLeft = -2;
          }
        }
      };
      const onData = (chunk: Buffer) => {
        if (done) return;
        pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
        try { drain(); } catch (error) { done = true; controller.error(error); socket.destroy(); }
      };
      socket.on("data", onData);
      socket.once("error", () => { if (!done) { done = true; controller.error(new TeeError("TEE_CONNECTION_FAILED")); } });
      socket.once("close", () => {
        if (done) return;
        done = true;
        // Only a close-delimited body may end with the connection.
        if (encoding !== "chunked" && remaining === Infinity) controller.close();
        else controller.error(new TeeError("TEE_CONNECTION_FAILED"));
      });
      try { drain(); } catch (error) { done = true; controller.error(error); socket.destroy(); }
    },
    cancel() { done = true; socket.destroy(); },
  });
}
