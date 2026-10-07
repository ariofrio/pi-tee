import https, { type AgentOptions } from "node:https";
import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import { TLSSocket } from "node:tls";
import { limitResponseBody, MAX_ENCRYPTED_RESPONSE_BYTES, readBoundedBody, TeeError } from "pi-tee-core";

/** One WebPKI-authenticated connection, then quote-bound SPKI approval before credentials. */
export class NearDirectChannel {
  private readonly agent: https.Agent;
  private socket?: TLSSocket;
  private peer?: string;
  private approved = false;
  private attempts = 0;
  private sent = false;
  private closed = false;
  private readonly onAbort = () => this.close();

  constructor(private readonly origin: string, private readonly signal: AbortSignal, trust: Pick<AgentOptions, "ca"> = {}) {
    this.agent = new https.Agent({ ...trust, keepAlive: true, maxSockets: 1, maxFreeSockets: 1, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", rejectUnauthorized: true });
    const create = this.agent.createConnection.bind(this.agent);
    this.agent.createConnection = (options, callback) => {
      if (++this.attempts !== 1 || this.closed) throw new TeeError("TEE_TLS_KEY_REJECTED");
      const socket = create(options, callback);
      if (!(socket instanceof TLSSocket)) throw new TeeError("TEE_RUNTIME_UNSUPPORTED");
      this.socket = socket;
      return socket;
    };
    signal.addEventListener("abort", this.onAbort, { once: true });
  }

  approve(fingerprint: string) {
    if (!this.socket || this.socket.destroyed || !this.socket.authorized || this.closed || fingerprint !== this.peer) {
      throw new TeeError("TEE_TLS_KEY_REJECTED");
    }
    this.approved = true;
  }

  async request(request: Request): Promise<{ response: Response; peerSpkiFingerprint: string }> {
    const url = new URL(request.url);
    const signal = AbortSignal.any([this.signal, request.signal]);
    signal.throwIfAborted();
    if (this.closed || this.socket?.destroyed) throw new TeeError("TEE_TLS_KEY_REJECTED");
    const params = url.searchParams;
    const evidence = request.method === "GET" && url.pathname === "/v1/attestation/report" &&
      /^[a-f0-9]{64}$/.test(params.get("nonce") ?? "") && params.get("include_tls_fingerprint") === "true" && params.get("signing_algo") === "ed25519" &&
      [...params].length === 3;
    const signature = request.method === "GET" && /^\/v1\/signature\/[^/]+$/.test(url.pathname) &&
      (url.search === "" || ([...params].length === 1 && params.get("signing_algo") === "ed25519"));
    const inference = request.method === "POST" && url.pathname === "/ohttp" && !url.search;
    if (url.origin !== this.origin || url.username || url.password || url.hash || !(evidence || signature || inference)) throw new TeeError("TEE_REQUEST_REJECTED");
    if ((request.method !== "GET" || request.headers.has("authorization")) && !this.approved) throw new TeeError("TEE_REQUEST_REJECTED");
    if (inference && this.sent) throw new TeeError("TEE_REQUEST_REJECTED");
    const payload = request.body ? await readBoundedBody(request.body, 16 * 1024 * 1024, signal) : undefined;
    signal.throwIfAborted();
    if (request.method === "POST") this.sent = true;
    return new Promise((resolve, reject) => {
      const req = https.request(url, {
        agent: this.agent, method: request.method, signal, rejectUnauthorized: true,
        headers: { ...Object.fromEntries(request.headers), "accept-encoding": "identity" },
      }, res => {
        try {
          const socket = res.socket;
          if (socket !== this.socket || !(socket instanceof TLSSocket) || !socket.authorized || socket.getProtocol() !== "TLSv1.3") throw new TeeError("TEE_TLS_KEY_REJECTED");
          // TLS 1.3 cannot renegotiate. Node may discard certificate metadata after reuse;
          // retain the first authenticated peer and require the identical socket above.
          if (!this.peer) {
            const cert = socket.getPeerX509Certificate();
            if (!cert) throw new TeeError("TEE_TLS_KEY_REJECTED");
            this.peer = createHash("sha256").update(cert.publicKey.export({ type: "spki", format: "der" })).digest("hex");
          }
          const headers = new Headers();
          for (const [name, value] of Object.entries(res.headers)) {
            if (typeof value === "string") headers.set(name, value);
            else if (value) for (const item of value) headers.append(name, item);
          }
          const response = new Response(Readable.toWeb(res) as ReadableStream<Uint8Array>, { status: res.statusCode, headers });
          resolve({ response: limitResponseBody(response, { signal, maxBytes: MAX_ENCRYPTED_RESPONSE_BYTES, cancel: () => req.destroy() }), peerSpkiFingerprint: this.peer });
        } catch (error) { req.destroy(); reject(error); }
      });
      req.once("error", reject);
      req.once("socket", socket => { if (socket !== this.socket) req.destroy(new TeeError("TEE_TLS_KEY_REJECTED")); });
      req.end(payload);
    });
  }

  readonly fetch: typeof globalThis.fetch = async (input, init) => (await this.request(new Request(input, init))).response;

  close() { this.closed = true; this.signal.removeEventListener("abort", this.onAbort); this.agent.destroy(); }
}
