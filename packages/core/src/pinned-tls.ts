import { createHash, X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import { connect, type TLSSocket } from "node:tls";
import { TeeError } from "./policy.js";
import { MAX_ENCRYPTED_RESPONSE_BYTES, MAX_REQUEST_BYTES, readBoundedBody } from "./transport.js";

const MAX_RESPONSE_HEADER_BYTES = 64 * 1024;
// Bytes queued for a stalled reader before the socket is paused.
const RESPONSE_HIGH_WATER_BYTES = 1024 * 1024;
// Bun keeps reading into native buffers while a socket is paused, so pausing
// cannot bound memory there. Instead every runtime fails a response whose
// received bytes exceed the transport's encrypted-response limit, and only
// Node pauses for a stalled reader.
const MAX_RECEIVED_RESPONSE_BYTES = MAX_ENCRYPTED_RESPONSE_BYTES + 1024 * 1024;
const CAN_PAUSE = !process.versions.bun;
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const HEADER_VALUE = /^[\t\x20-\x7e\x80-\xff]*$/;
const FORBIDDEN_REQUEST_HEADERS = new Set(["host", "connection", "content-length", "transfer-encoding", "keep-alive", "upgrade", "te", "trailer", "expect"]);

/** Credentials are transmitted only after the exact socket presents the attested SPKI. */
export function pinnedTlsFetch(endpoint: string, fingerprint: string, expiresAt?: number): typeof globalThis.fetch {
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw new TeeError("TEE_REQUEST_REJECTED");
  return socketTlsFetch(endpoint, fingerprint, expiresAt);
}

/** Unattested gateway: WebPKI authorizes metadata delivery; EHBP protects bodies. */
export function webPkiTlsFetch(endpoint: string, expiresAt?: number): typeof globalThis.fetch {
  return socketTlsFetch(endpoint, undefined, expiresAt);
}

function socketTlsFetch(endpoint: string, fingerprint: string | undefined, expiresAt?: number): typeof globalThis.fetch {
  const target = new URL(endpoint);
  if (target.protocol !== "https:" || target.username || target.password || target.search || target.hash ||
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
      // An attested SPKI replaces WebPKI authorization when supplied. No HTTP is written before authorization.
      rejectUnauthorized: fingerprint === undefined, minVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"],
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
            if (fingerprint !== undefined) {
              const certificate = socket.getPeerCertificate().raw;
              if (!certificate) throw new TeeError("TEE_TLS_KEY_REJECTED");
              const spki = new X509Certificate(certificate).publicKey.export({ type: "spki", format: "der" });
              if (createHash("sha256").update(spki).digest("hex") !== fingerprint) throw new TeeError("TEE_TLS_KEY_REJECTED");
            }
            // Bun ignores minVersion, so check the negotiated version on every runtime.
            if (socket.getProtocol() !== "TLSv1.3") throw new TeeError("TEE_TLS_KEY_REJECTED");
            resolve();
          } catch { reject(new TeeError("TEE_TLS_KEY_REJECTED")); }
        });
      });
      clearTimeout(connectionTimeout);
      signal.throwIfAborted();
      if (expiresAt !== undefined && Date.now() >= expiresAt) throw new TeeError("TEE_PUBLIC_SESSION_REJECTED");
      // One request per connection: no keep-alive, pipelining or reuse.
      writeHttpRequest(socket, "POST", target, request.headers, body, "close");
      return await readHttpResponse(socket, signal);
    } catch (error) {
      clearTimeout(connectionTimeout);
      signal.removeEventListener("abort", abort);
      socket.destroy();
      if (signal.aborted) throw signal.reason ?? error;
      throw error instanceof TeeError ? error : new TeeError("TEE_CONNECTION_FAILED");
    }
  };
}

/** Writes one HTTP/1.1 request head and body on a socket the caller has already verified. */
export function writeHttpRequest(socket: TLSSocket, method: "GET" | "POST", target: URL, headers: Headers, body: Uint8Array | undefined, connection: "close" | "keep-alive") {
  const lines = [`${method} ${target.pathname}${target.search} HTTP/1.1`, `Host: ${target.host}`];
  for (const [name, value] of headers) {
    if (FORBIDDEN_REQUEST_HEADERS.has(name) || /[\r\n]/.test(name) || /[\r\n]/.test(value)) continue;
    lines.push(`${name}: ${value}`);
  }
  if (body || method === "POST") lines.push(`Content-Length: ${body?.length ?? 0}`);
  lines.push(`Connection: ${connection}`, "", "");
  socket.write(Buffer.concat([Buffer.from(lines.join("\r\n"), "latin1"), Buffer.from(body ?? [])]));
}

/**
 * Minimal HTTP/1.1 response reader. Bun's https.Agent cannot adopt an
 * externally verified socket, so the verified socket carries requests directly.
 * Without `onRelease`, the exchange owns the socket and destroys it when done.
 * With `onRelease`, a cleanly framed response hands the socket back through
 * `onRelease(true)` only if it may carry another request; any other outcome
 * destroys it. Unread bytes after a response are never reused.
 */
export function readHttpResponse(socket: TLSSocket, signal: AbortSignal, onRelease?: (reusable: boolean) => void): Promise<Response> {
  let released = false;
  const release = onRelease && ((reusable: boolean) => { if (!released) { released = true; onRelease(reusable); } });
  return new Promise<Response>((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    let settled = false;
    const detach = () => { socket.off("data", onData); socket.off("error", fail); socket.off("close", onClose); };
    const fail = (error: unknown) => { detach(); if (!settled) { settled = true; reject(error); } release?.(false); socket.destroy(); };
    const onClose = () => fail(new TeeError("TEE_CONNECTION_FAILED"));
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
          const name = line.slice(0, colon), value = line.slice(colon + 1).trim();
          if (colon <= 0 || !HEADER_NAME.test(name) || !HEADER_VALUE.test(value)) return fail(new TeeError("TEE_RESPONSE_REJECTED"));
          try { headers.append(name, value); } catch { return fail(new TeeError("TEE_RESPONSE_REJECTED")); }
        }
        const keepAlive = release && status[0]!.startsWith("HTTP/1.1 ") && !/(^|,)\s*close\s*(,|$)/i.test(headers.get("connection") ?? "")
          ? release : undefined;
        let stream: ReadableStream<Uint8Array> | null = null;
        if ([204, 205, 304].includes(code)) {
          if (keepAlive && (headers.has("transfer-encoding") || rest.length)) return fail(new TeeError("TEE_RESPONSE_REJECTED"));
          detach();
          if (keepAlive) keepAlive(true); else { release?.(false); socket.destroy(); }
        } else {
          detach();
          try { stream = bodyStream(socket, headers, rest, signal, keepAlive); } catch (error) { return fail(error); }
        }
        settled = true;
        resolve(new Response(stream, { status: code, headers }));
        return;
      }
    };
    // Node may have paused a reused socket for a stalled previous reader.
    if (CAN_PAUSE) socket.resume();
    socket.on("data", onData);
    socket.once("error", fail);
    socket.once("close", onClose);
  });
}

function bodyStream(socket: TLSSocket, headers: Headers, initial: Buffer, signal: AbortSignal, release?: (reusable: boolean) => void): ReadableStream<Uint8Array> {
  const encoding = headers.get("transfer-encoding")?.toLowerCase();
  const declared = headers.get("content-length");
  if (encoding !== undefined && encoding !== null && encoding !== "chunked") { socket.destroy(); throw new TeeError("TEE_RESPONSE_REJECTED"); }
  // A close-delimited body could be truncated by anyone on the path who
  // closes the TCP connection; accept only self-delimiting framing.
  if (encoding !== "chunked" && (declared === null || !/^[0-9]{1,15}$/.test(declared))) { socket.destroy(); throw new TeeError("TEE_RESPONSE_REJECTED"); }
  let remaining = encoding === "chunked" ? 0 : Number(declared);
  let pending = initial;
  // chunked: bytes left in the current chunk; -1 awaiting a size line, -2 awaiting CRLF, -3 awaiting the trailer section's end
  let chunkLeft = -1;
  let trailerBytes = 0;
  let done = false;
  let detach = () => {};
  // A released socket stays open for the owner's next request only if nothing follows the framed body.
  const end = (clean: boolean) => {
    done = true;
    detach();
    if (clean && release && !pending.length) release(true);
    else { release?.(false); socket.destroy(); }
  };
  return new ReadableStream<Uint8Array>({
    start(controller) {
      const enqueue = (bytes: Buffer) => {
        controller.enqueue(new Uint8Array(bytes));
        if (CAN_PAUSE && (controller.desiredSize ?? 0) <= 0) socket.pause();
      };
      const fail = (error: unknown) => { if (!done) { controller.error(error); end(false); } else socket.destroy(); };
      const abort = () => fail(new TeeError("TEE_CONNECTION_FAILED"));
      const complete = () => { end(true); controller.close(); };
      const drain = () => {
        if (encoding !== "chunked") {
          if (pending.length) {
            const take = pending.subarray(0, Math.min(pending.length, remaining));
            remaining -= take.length; pending = pending.subarray(take.length);
            if (take.length) enqueue(take);
          }
          if (remaining === 0) complete();
          return;
        }
        for (;;) {
          if (chunkLeft === -1 || chunkLeft === -3) {
            const line = pending.indexOf("\r\n");
            if (line < 0) { if (pending.length > 1024) throw new TeeError("TEE_RESPONSE_REJECTED"); return; }
            const text = pending.subarray(0, line).toString("latin1");
            pending = pending.subarray(line + 2);
            if (chunkLeft === -3) {
              trailerBytes += line + 2;
              if (trailerBytes > MAX_RESPONSE_HEADER_BYTES) throw new TeeError("TEE_RESPONSE_REJECTED");
              if (!text) return complete();
              continue;
            }
            const size = /^([0-9a-fA-F]{1,8})(?:;.*)?$/.exec(text);
            if (!size) throw new TeeError("TEE_RESPONSE_REJECTED");
            chunkLeft = Number.parseInt(size[1]!, 16);
            if (chunkLeft === 0) {
              // A reused connection must also consume the trailer section; a closing one ends here.
              if (!release) return complete();
              chunkLeft = -3;
            }
          } else if (chunkLeft === -2) {
            if (pending.length < 2) return;
            if (pending[0] !== 13 || pending[1] !== 10) throw new TeeError("TEE_RESPONSE_REJECTED");
            pending = pending.subarray(2); chunkLeft = -1;
          } else {
            if (!pending.length) return;
            const take = pending.subarray(0, Math.min(pending.length, chunkLeft));
            pending = pending.subarray(take.length); chunkLeft -= take.length;
            enqueue(take);
            if (chunkLeft === 0) chunkLeft = -2;
          }
        }
      };
      let received = initial.length;
      const onData = (chunk: Buffer) => {
        if (done) return;
        received += chunk.length;
        if (received > MAX_RECEIVED_RESPONSE_BYTES) return fail(new TeeError("TEE_RESPONSE_REJECTED"));
        pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
        try { drain(); } catch (error) { fail(error); }
      };
      const onError = () => fail(new TeeError("TEE_CONNECTION_FAILED"));
      detach = () => {
        socket.off("data", onData); socket.off("error", onError); socket.off("close", onError);
        signal.removeEventListener("abort", abort);
      };
      signal.addEventListener("abort", abort, { once: true });
      socket.on("data", onData);
      socket.once("error", onError);
      socket.once("close", onError);
      try { drain(); } catch (error) { fail(error); }
    },
    pull() { if (!done && CAN_PAUSE) socket.resume(); },
    cancel() { if (!done) end(false); socket.destroy(); },
  }, { highWaterMark: RESPONSE_HIGH_WATER_BYTES, size: chunk => chunk.byteLength });
}
