import { createHash, X509Certificate } from "node:crypto";
import { Agent, request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { addAbortSignal, Readable } from "node:stream";
import { connect } from "node:tls";
import { TeeError } from "./policy.js";
import { MAX_REQUEST_BYTES, readBoundedBody } from "./transport.js";

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
    const socket = addAbortSignal(signal, connect({
      host: target.hostname, port: Number(target.port || 443),
      servername: isIP(target.hostname) ? undefined : target.hostname,
      // Attested SPKI replaces WebPKI authorization. No HTTP is created before checking it.
      rejectUnauthorized: false, minVersion: "TLSv1.3",
    }));
    const connectionTimeout = setTimeout(() => socket.destroy(new TeeError("TEE_CONNECTION_FAILED")), 10000);
    const agent = new Agent({ keepAlive: false });
    try {
      await new Promise<void>((resolve, reject) => {
        socket.once("error", reject);
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
      agent.createConnection = () => socket;
      return await new Promise<Response>((resolve, reject) => {
        const outgoing = httpsRequest(target, {
          method: "POST", agent, signal, headers: Object.fromEntries(request.headers),
        }, incoming => {
          const headers = new Headers();
          for (let i = 0; i < incoming.rawHeaders.length; i += 2) headers.append(incoming.rawHeaders[i]!, incoming.rawHeaders[i + 1]!);
          incoming.once("close", () => agent.destroy());
          const status = incoming.statusCode ?? 502;
          resolve(new Response([204, 205, 304].includes(status) ? null : Readable.toWeb(incoming) as ReadableStream<Uint8Array>, { status, headers }));
        });
        outgoing.once("socket", connected => {
          if (connected !== socket) {
            connected.destroy();
            outgoing.destroy(new TeeError("TEE_TLS_KEY_REJECTED"));
          }
        });
        outgoing.once("error", error => { agent.destroy(); reject(error); });
        outgoing.end(body);
      });
    } catch (error) {
      clearTimeout(connectionTimeout);
      agent.destroy();
      socket.destroy();
      throw error;
    }
  };
}
