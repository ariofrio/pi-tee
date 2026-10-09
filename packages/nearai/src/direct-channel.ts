import { createHash, X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import { connect, type ConnectionOptions, type TLSSocket } from "node:tls";
import { limitResponseBody, MAX_ENCRYPTED_RESPONSE_BYTES, readBoundedBody, readHttpResponse, TeeError, withAbort, writeHttpRequest } from "pi-tee-core";

/**
 * One WebPKI-authenticated TLS 1.3 connection, then quote-bound SPKI approval before credentials.
 * Requests take turns as HTTP/1.1 exchanges on that socket, written directly with `node:tls`
 * because Bun's https.Agent cannot be bound to one socket. The connection is never replaced.
 * The gateway scope admits the NEAR gateway's model metadata and model evidence for one model;
 * the gateway requires the API key for its evidence, so signatures and inference wait for approval there.
 */
export class NearDirectChannel {
  private socket?: TLSSocket;
  private connecting?: Promise<TLSSocket>;
  private peer?: string;
  private approved = false;
  private sent = false;
  private closed = false;
  private turn: Promise<unknown> = Promise.resolve();
  private readonly lifetime = new AbortController();
  private readonly onAbort = () => this.close();
  // Between exchanges the peer has nothing to say; anything it sends ends the channel.
  private readonly onIdleData = () => this.close();

  constructor(private readonly origin: string, private readonly signal: AbortSignal, private readonly trust: Pick<ConnectionOptions, "ca"> = {},
    private readonly scope: { gatewayModel?: string } = {}) {
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
    const model = this.scope.gatewayModel;
    const metadata = model !== undefined && request.method === "GET" && url.pathname === `/v1/model/${encodeURIComponent(model)}` && !url.search;
    const modelEvidence = model !== undefined && request.method === "GET" && url.pathname === "/v1/attestation/report" &&
      params.get("model") === model && params.get("provider") === "near" && /^[a-f0-9]{64}$/.test(params.get("nonce") ?? "") &&
      params.get("include_tls_fingerprint") === "false" && params.get("signing_algo") === "ed25519" && [...params].length === 5;
    if (url.origin !== this.origin || url.username || url.password || url.hash || !(evidence || signature || inference || metadata || modelEvidence)) throw new TeeError("TEE_REQUEST_REJECTED");
    // The gateway needs its key for evidence and metadata; nothing else, and no other headers, go before approval.
    const early = model === undefined ? request.method === "GET" && !request.headers.has("authorization") :
      (evidence || metadata || modelEvidence) && [...request.headers.keys()].every(name => name === "authorization" || name === "x-no-aliasing");
    if (!early && !this.approved) throw new TeeError("TEE_REQUEST_REJECTED");
    // Reserved before the first await, so concurrent dispatches cannot both pass.
    if (request.method === "POST") {
      if (this.sent) throw new TeeError("TEE_REQUEST_REJECTED");
      this.sent = true;
    }
    const payload = request.body ? await readBoundedBody(request.body, 16 * 1024 * 1024, signal) : undefined;
    signal.throwIfAborted();
    // The next request is written only after the previous response has been read to its end.
    const previous = this.turn;
    let done!: () => void;
    const mine = new Promise<void>(resolve => { done = resolve; });
    this.turn = Promise.all([previous, mine]);
    const release = (reusable: boolean) => {
      if (reusable && !this.closed && this.socket && !this.socket.destroyed) this.socket.on("data", this.onIdleData);
      else this.close();
      done();
    };
    const waiting = AbortSignal.any([signal, this.lifetime.signal]);
    let written = false;
    try {
      await withAbort(previous, waiting);
      const socket = await withAbort(this.open(), waiting);
      if (this.closed || socket.destroyed) throw new TeeError("TEE_TLS_KEY_REJECTED");
      socket.off("data", this.onIdleData);
      const headers = new Headers(request.headers);
      headers.set("accept-encoding", "identity");
      written = true;
      writeHttpRequest(socket, request.method as "GET" | "POST", url, headers, payload, "keep-alive");
      const response = await readHttpResponse(socket, signal, release);
      return {
        response: limitResponseBody(response, { signal, maxBytes: MAX_ENCRYPTED_RESPONSE_BYTES, cancel: () => this.close() }),
        peerSpkiFingerprint: this.peer!,
      };
    } catch (error) {
      // A request that never reached the socket leaves the connection as it was.
      if (written) this.close();
      done();
      if (signal.aborted) throw signal.reason ?? error;
      throw this.closed && !(error instanceof TeeError) ? new TeeError("TEE_TLS_KEY_REJECTED") : error;
    }
  }

  readonly fetch: typeof globalThis.fetch = async (input, init) => (await this.request(new Request(input, init))).response;

  close() {
    this.closed = true;
    this.signal.removeEventListener("abort", this.onAbort);
    this.lifetime.abort();
    this.socket?.destroy();
  }

  // Exactly one connection attempt per channel; a failed or closed connection is never replaced.
  private open(): Promise<TLSSocket> {
    if (this.connecting) return this.connecting.then(socket => {
      if (this.closed || socket.destroyed) throw new TeeError("TEE_TLS_KEY_REJECTED");
      return socket;
    });
    const target = new URL(this.origin);
    this.connecting = new Promise<TLSSocket>((resolve, reject) => {
      const socket = connect({
        ...this.trust, host: target.hostname, port: Number(target.port || 443),
        servername: isIP(target.hostname) ? undefined : target.hostname,
        rejectUnauthorized: true, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"],
      });
      this.socket = socket;
      const timeout = setTimeout(() => socket.destroy(new TeeError("TEE_CONNECTION_FAILED")), 10000);
      const fail = (error: unknown) => {
        clearTimeout(timeout);
        this.close();
        const code = String((error as { code?: unknown } | undefined)?.code ?? "");
        reject(error instanceof TeeError ? error : new TeeError(/CERT|SELF_SIGNED|UNABLE_TO|HOSTNAME|ALTNAME|TLS/.test(code) ? "TEE_TLS_KEY_REJECTED" : "TEE_CONNECTION_FAILED"));
      };
      socket.once("error", fail);
      socket.once("close", () => fail(new TeeError("TEE_CONNECTION_FAILED")));
      socket.once("secureConnect", () => {
        clearTimeout(timeout);
        try {
          // Bun ignores minVersion, so check the negotiated version on every runtime.
          if (!socket.authorized || socket.getProtocol() !== "TLSv1.3" || (socket.alpnProtocol && socket.alpnProtocol !== "http/1.1")) throw new TeeError("TEE_TLS_KEY_REJECTED");
          const certificate = socket.getPeerCertificate().raw;
          if (!certificate) throw new TeeError("TEE_TLS_KEY_REJECTED");
          this.peer = createHash("sha256").update(new X509Certificate(certificate).publicKey.export({ type: "spki", format: "der" })).digest("hex");
        } catch { return fail(new TeeError("TEE_TLS_KEY_REJECTED")); }
        socket.off("error", fail);
        socket.on("error", () => this.close());
        resolve(socket);
      });
    });
    this.connecting.catch(() => undefined);
    return this.connecting;
  }
}
