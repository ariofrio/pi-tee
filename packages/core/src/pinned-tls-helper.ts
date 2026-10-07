import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { tmpdir } from "node:os";
import { TeeError } from "./policy.js";
import { MAX_REQUEST_BYTES, readBoundedBody, withAbort } from "./transport.js";

const INIT = 1, READY = 2, REQUEST = 3, RESPONSE = 4, BODY = 5, END = 6, ERROR = 7;
const helperErrors = new Set(["TEE_REQUEST_REJECTED", "TEE_TLS_KEY_REJECTED", "TEE_CONNECTION_FAILED", "TEE_PUBLIC_SESSION_REJECTED"]);

function frame(kind: number, data = Buffer.alloc(0)) {
  const bytes = Buffer.alloc(5 + data.length);
  bytes[0] = kind; bytes.writeUInt32BE(data.length, 1); data.copy(bytes, 5);
  return bytes;
}

class Frames {
  private iterator: AsyncIterator<Buffer>;
  private pending = Buffer.alloc(0);
  constructor(source: AsyncIterable<Buffer>) { this.iterator = source[Symbol.asyncIterator](); }
  private async read(size: number): Promise<Buffer> {
    while (this.pending.length < size) {
      const next = await this.iterator.next();
      if (next.done) throw new TeeError("TEE_CONNECTION_FAILED");
      if (this.pending.length + next.value.length > 256 * 1024) throw new TeeError("TEE_CONNECTION_FAILED");
      this.pending = Buffer.concat([this.pending, next.value]);
    }
    const result = this.pending.subarray(0, size);
    this.pending = this.pending.subarray(size);
    return result;
  }
  async next() {
    const header = await this.read(5);
    const size = header.readUInt32BE(1);
    if (size > 64 * 1024) throw new TeeError("TEE_CONNECTION_FAILED");
    const data = await this.read(size);
    if (header[0] === ERROR) {
      const code = data.toString("utf8");
      throw new TeeError(helperErrors.has(code) ? code : "TEE_CONNECTION_FAILED");
    }
    return { kind: header[0], data };
  }
}

/** Optional portable transport. Adapters must supply a reviewed platform artifact digest. */
export function pinnedTlsHelperFetch(endpoint: string, fingerprint: string, artifact: {
  helperPath: string; sha256: string;
}, expiresAt?: number): typeof globalThis.fetch {
  const target = new URL(endpoint);
  const { helperPath, sha256 } = artifact;
  if (target.protocol !== "https:" || target.username || target.password || target.search || target.hash ||
      target.pathname !== "/v1/chat/completions" || !/^[a-f0-9]{64}$/.test(fingerprint) ||
      !isAbsolute(helperPath) || !/^[a-f0-9]{64}$/.test(sha256) ||
      (expiresAt !== undefined && (!Number.isSafeInteger(expiresAt) || expiresAt <= 0))) throw new TeeError("TEE_REQUEST_REJECTED");
  return async (input, init) => {
    const request = new Request(input, init);
    if (request.url !== endpoint || request.method !== "POST") throw new TeeError("TEE_REQUEST_REJECTED");
    const signal = request.signal;
    const body = await readBoundedBody(request.body, MAX_REQUEST_BYTES, signal);
    signal.throwIfAborted();
    let bytes: Buffer;
    try {
      if ((await stat(helperPath)).size > 64 * 1024 * 1024) throw new Error("size");
      bytes = await readFile(helperPath, { signal });
    } catch { signal.throwIfAborted(); throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED"); }
    if (createHash("sha256").update(bytes).digest("hex") !== sha256) throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED");
    const directory = await mkdtemp(join(tmpdir(), "pi-tee-tls-"));
    const snapshot = join(directory, process.platform === "win32" ? "pinned-tls.exe" : "pinned-tls");
    try { await writeFile(snapshot, bytes, { flag: "wx", mode: 0o500, signal }); }
    catch (error) { await rm(directory, { recursive: true, force: true }); throw error; }
    bytes = Buffer.alloc(0);
    const child = spawn(snapshot, [], {
      env: { TZ: "UTC", ...(process.platform === "win32" ? { SystemRoot: process.env.SystemRoot } : {}) },
      stdio: ["pipe", "pipe", "ignore"], windowsHide: true,
    });
    let finished = false;
    const closed = new Promise<void>(resolve => { child.once("close", () => resolve()); child.once("error", () => resolve()); });
    child.stdin.on("error", () => {});
    child.stdout.on("error", () => {});
    const stop = () => {
      if (finished) return;
      finished = true;
      signal.removeEventListener("abort", stop);
      child.stdin.destroy(); child.stdout.destroy(); child.kill();
      const force = setTimeout(() => child.kill("SIGKILL"), 1000);
      void closed.then(async () => {
        clearTimeout(force);
        await rm(directory, { recursive: true, force: true, maxRetries: 4, retryDelay: 250 });
      }).catch(() => undefined);
    };
    signal.addEventListener("abort", stop, { once: true });
    const frames = new Frames(child.stdout);
    const next = () => withAbort(frames.next(), signal);
    const write = (value: Buffer) => withAbort(new Promise<void>((resolve, reject) => {
      child.stdin.write(value, error => error ? reject(new TeeError("TEE_CONNECTION_FAILED")) : resolve());
    }), signal);
    try {
      signal.throwIfAborted();
      await write(frame(INIT, Buffer.from(JSON.stringify({ endpoint, fingerprint, expiresAt }))));
      const ready = await next();
      if (ready.kind !== READY || ready.data.length) throw new TeeError("TEE_CONNECTION_FAILED");
      signal.throwIfAborted();
      if (expiresAt !== undefined && Date.now() >= expiresAt) throw new TeeError("TEE_PUBLIC_SESSION_REJECTED");
      // The helper has authenticated its sole socket; only now send secrets to it.
      await write(frame(REQUEST, Buffer.from(JSON.stringify({ headers: Object.fromEntries(request.headers), body: Buffer.from(body).toString("base64") }))));
      const incoming = await next();
      if (incoming.kind !== RESPONSE) throw new TeeError("TEE_CONNECTION_FAILED");
      const metadata = JSON.parse(incoming.data.toString("utf8"));
      if (!Number.isInteger(metadata.status) || metadata.status < 200 || metadata.status > 599 ||
          metadata.headers === null || typeof metadata.headers !== "object" || Array.isArray(metadata.headers)) throw new TeeError("TEE_CONNECTION_FAILED");
      const headers = new Headers();
      for (const [name, values] of Object.entries(metadata.headers)) {
        if (!Array.isArray(values) || !values.every(value => typeof value === "string")) throw new TeeError("TEE_CONNECTION_FAILED");
        for (const value of values) headers.append(name, value);
      }
      const stream = new ReadableStream<Uint8Array>({
        async pull(controller) {
          try {
            const chunk = await next();
            if (chunk.kind === BODY && chunk.data.length) controller.enqueue(chunk.data);
            else if (chunk.kind === END && !chunk.data.length) { controller.close(); stop(); }
            else throw new TeeError("TEE_CONNECTION_FAILED");
          } catch (error) { controller.error(error); stop(); }
        },
        cancel: stop,
      }, { highWaterMark: 0 });
      if ([204, 205, 304].includes(metadata.status)) {
        await stream.cancel();
        return new Response(null, { status: metadata.status, headers });
      }
      return new Response(stream, { status: metadata.status, headers });
    } catch (error) { stop(); throw error; }
  };
}
