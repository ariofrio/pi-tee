// Research probe only; not an Approved transport or a registered Pi provider.
// Evidence-only by default. --infer sends one fixed, capped synthetic prompt.
import assert from "node:assert/strict";
import https from "node:https";
import { createHash } from "node:crypto";
import {
  DirectAttestationClient,
  DirectInferenceClient,
  verifyDirectModelAttestations,
} from "@nearai/inference-sdk/node";
const args = process.argv.slice(2).filter((arg) => arg !== "--infer");
const domain = args[0] ?? "glm-5-3-flash.completions.near.ai";
const model = args[1] ?? "z-ai/glm-5.3-flash";
const infer = process.argv.includes("--infer");
assert.match(domain, /^[a-z0-9-]+\.completions\.near\.ai$/);
const baseUrl = `https://${domain}/v1/`;
const deadline = AbortSignal.timeout(90000);
const fetch0 = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const request = new Request(input, init);
  return fetch0(
    new Request(request, {
      signal: AbortSignal.any([deadline, request.signal]),
    }),
  );
};
class Channel {
  constructor() {
    this.socket = undefined;
    this.peer = undefined;
    this.approved = false;
    this.attempts = 0;
    this.sent = 0;
    this.paths = [];
    this.agent = new https.Agent({
      keepAlive: true,
      maxSockets: 1,
      maxFreeSockets: 1,
      minVersion: "TLSv1.3",
      maxVersion: "TLSv1.3",
    });
    const create = this.agent.createConnection.bind(this.agent);
    this.agent.createConnection = (options, callback) => {
      if (++this.attempts !== 1) throw Error("DIRECT_RECONNECT_BLOCKED");
      this.socket = create(options, callback);
      return this.socket;
    };
  }
  approve(fingerprint) {
    assert.ok(
      this.socket && !this.socket.destroyed && this.socket.authorized,
      "DIRECT_CHANNEL_LOST",
    );
    assert.equal(fingerprint, this.peer, "DIRECT_PEER_MISMATCH");
    this.approved = true;
  }
  async request(request) {
    const url = new URL(request.url);
    assert.equal(url.origin, new URL(baseUrl).origin, "DIRECT_ORIGIN_REJECTED");
    if (this.socket?.destroyed) throw Error("DIRECT_CHANNEL_LOST");
    if (request.method !== "GET" || request.headers.has("authorization"))
      assert.ok(this.approved, "DIRECT_PREFLIGHT_REQUIRED");
    const payload = request.body
      ? new Uint8Array(await request.arrayBuffer())
      : undefined;
    if (payload) assert.ok(payload.byteLength <= 16 * 1024 * 1024);
    if (request.method === "POST") {
      assert.equal(this.sent, 0, "DIRECT_PROMPT_LIMIT");
      this.sent++;
    }
    return new Promise((resolve, reject) => {
      const req = https.request(
        url,
        {
          agent: this.agent,
          method: request.method,
          headers: {
            ...Object.fromEntries(request.headers),
            "accept-encoding": "identity",
          },
          signal: AbortSignal.any([deadline, request.signal]),
          rejectUnauthorized: true,
        },
        (res) => {
          const socket = res.socket;
          try {
            assert.equal(socket, this.socket, "DIRECT_SOCKET_MISMATCH");
            assert.equal(socket.getProtocol(), "TLSv1.3");
            if (!this.peer) {
              const cert = socket.getPeerX509Certificate();
              assert.ok(cert, "DIRECT_CERTIFICATE_REQUIRED");
              this.peer = createHash("sha256")
                .update(cert.publicKey.export({ type: "spki", format: "der" }))
                .digest("hex");
            }
          } catch (error) {
            req.destroy();
            reject(error);
            return;
          }
          const chunks = [];
          let size = 0;
          res.on("data", (chunk) => {
            size += chunk.length;
            if (size > 8 * 1024 * 1024) req.destroy(Error("DIRECT_BODY_LIMIT"));
            else chunks.push(chunk);
          });
          res.on("error", reject);
          res.on("end", () => {
            this.paths.push(url.pathname);
            resolve({
              response: new Response(Buffer.concat(chunks), {
                status: res.statusCode,
                headers: Object.entries(res.headers).filter(
                  ([, v]) => typeof v === "string",
                ),
              }),
              peerSpkiFingerprint: this.peer,
            });
          });
        },
      );
      req.once("error", reject);
      req.once("socket", (socket) => {
        if (socket !== this.socket)
          req.destroy(Error("DIRECT_SOCKET_MISMATCH"));
      });
      req.end(payload);
    });
  }
  async fetch(input, init) {
    return (await this.request(new Request(input, init))).response;
  }
  close() {
    this.agent.destroy();
  }
}
const channel = new Channel();
let fetched;
let verified;
class BoundEvidence extends DirectAttestationClient {
  fetchModelAttestations() {
    return this.fetchModelAttestationsWithOptions({
      signingAlgo: "ed25519",
      includeSpkiFingerprint: true,
    });
  }
  requestAttestation(request) {
    return channel.request(request);
  }
  requestApi(request) {
    if (infer && process.env.NEARAI_API_KEY)
      request.headers.set(
        "authorization",
        `Bearer ${process.env.NEARAI_API_KEY}`,
      );
    return channel.fetch(request);
  }
}
const evidence = new BoundEvidence({ baseUrl });
class BoundInference extends DirectInferenceClient {
  async fetchModelAttestations() {
    fetched = await evidence.fetchModelAttestations();
    return fetched;
  }
  createDirectSessionTransport({ tlsBinding, attestations }) {
    verified = { tlsBinding, attestations };
    assert.equal(tlsBinding.kind, "attested", "DIRECT_TLS_BINDING_REQUIRED");
    channel.approve(tlsBinding.spkiFingerprint);
    return {
      fetch: channel.fetch.bind(channel),
      fetchCompletionSignature: (params) =>
        evidence.fetchCompletionSignature(params),
    };
  }
}
const result = {
  domain,
  model,
  mode: infer ? "synthetic-inference" : "evidence-only",
  checkedAt: new Date().toISOString(),
};
try {
  const client = new BoundInference({
    baseUrl,
    ...(infer ? { apiKey: process.env.NEARAI_API_KEY } : {}),
    signingAlgo: "ed25519",
    e2ee: true,
    ohttp: true,
    attestationCacheTimeToLiveMs: 0,
    responseCacheTimeToLiveMs: 60000,
    modelVerification: {
      policy: { acceptedTcbStatuses: ["UpToDate"], gpuEvidence: "required" },
    },
  });
  if (!infer) {
    await client.verify(model);
    Object.assign(result, {
      verified: true,
      tlsBinding: verified.tlsBinding.kind,
      cpu: verified.attestations.map((x) => x.tcbStatus),
      gpu: verified.attestations.map((x) => x.gpuEvidence),
      returnedReports: verified.attestations.length,
    });
    try {
      await verifyDirectModelAttestations({
        ...fetched,
        clientBinding: { ...fetched.clientBinding, nonce: "00".repeat(32) },
        policy: { acceptedTcbStatuses: ["UpToDate"], gpuEvidence: "required" },
      });
      result.nonceMismatchRejected = false;
    } catch (error) {
      result.nonceMismatchRejected =
        error?.failure?.code === "binding.nonce_mismatch";
    }
    try {
      await verifyDirectModelAttestations({
        ...fetched,
        clientBinding: {
          ...fetched.clientBinding,
          spkiFingerprint: "00".repeat(32),
        },
        policy: { acceptedTcbStatuses: ["UpToDate"], gpuEvidence: "required" },
      });
      result.peerMismatchRejected = false;
    } catch (error) {
      result.peerMismatchRejected =
        error?.failure?.code === "binding.spki_fingerprint_mismatch";
    }
    await channel.fetch(new Request(new URL("models", baseUrl)));
    result.secondRequestOnSameSocket = true;
  } else {
    assert.ok(process.env.NEARAI_API_KEY, "DIRECT_KEY_REQUIRED");
    const response = await client.fetch(
      new Request(new URL("chat/completions", baseUrl), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model,
          messages: [
            { role: "user", content: "Reply with exactly DIRECT_ACCESS_OK." },
          ],
          stream: true,
          stream_options: { include_usage: true },
          max_tokens: 128,
          temperature: 0,
          chat_template_kwargs: { enable_thinking: false },
        }),
        signal: deadline,
      }),
    );
    result.httpStatus = response.status;
    assert.equal(response.status, 200, "DIRECT_INFERENCE_STATUS");
    const text = await response.text();
    let id;
    let content = "";
    let usage = false;
    for (const line of text.split("\n")) {
      if (!line.startsWith("data: ") || line === "data: [DONE]") continue;
      const v = JSON.parse(line.slice(6));
      id ??= v.id;
      for (const c of v.choices ?? [])
        if (typeof c.delta?.content === "string") content += c.delta.content;
      usage ||= (v.usage?.total_tokens ?? 0) > 0;
    }
    assert.ok(id, "DIRECT_COMPLETION_ID_REQUIRED");
    const signed = await client.verifyResponse(id);
    assert.equal(signed.signatureKind, "provider_tee");
    Object.assign(result, {
      responseSignatureVerified: true,
      syntheticMarker: content.includes("DIRECT_ACCESS_OK"),
      usageReturned: usage,
      cpu: verified.attestations.map((x) => x.tcbStatus),
      gpu: verified.attestations.map((x) => x.gpuEvidence),
      tlsBinding: verified.tlsBinding.kind,
    });
  }
  channel.close();
  try {
    await channel.fetch(new Request(new URL("models", baseUrl)));
    result.reconnectRejected = false;
  } catch {
    result.reconnectRejected = true;
  }
} catch (error) {
  result.errorClass = error?.constructor?.name;
  result.failure =
    error?.failure?.code ??
    (error instanceof assert.AssertionError
      ? error.message.split("\n")[0]
      : ["DIRECT_RECONNECT_BLOCKED", "DIRECT_CHANNEL_LOST"].includes(
            error?.message,
          )
        ? error.message
        : "unclassified");
  if (error?.failure?.code === "policy.tcb_status_not_allowed")
    result.tcbStatus =
      error.failure.details?.actual ?? error.failure.details?.tcbStatus;
} finally {
  channel.close();
  Object.assign(result, {
    tlsConnectionAttempts: channel.attempts,
    logicalChatRequests: channel.sent,
    paths: channel.paths.map((path) =>
      path.startsWith("/v1/signature/") ? "/v1/signature/{id}" : path,
    ),
  });
}
console.log(JSON.stringify(result));
if (
  result.failure ||
  result.reconnectRejected !== true ||
  (!infer &&
    (result.nonceMismatchRejected !== true ||
      result.peerMismatchRejected !== true)) ||
  (infer && (!result.syntheticMarker || !result.usageReturned))
)
  process.exitCode = 1;
