import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { createServer } from "node:https";
import { createServer as createTlsServer, type TLSSocket } from "node:tls";
import { join, resolve } from "node:path";
import { NearDirectChannel } from "../packages/nearai/src/direct-channel.js";
import { assertNearRuntime } from "../packages/nearai/src/index.js";

const evidencePath = `/v1/attestation/report?nonce=${"11".repeat(32)}&include_tls_fingerprint=true&signing_algo=ed25519`;

async function localhostCertificate() {
  await mkdir(".scratch/work", { recursive: true });
  const dir = await mkdtemp(resolve(".scratch/work/near-tls-"));
  const certPath = join(dir, "cert.pem");
  const keyPath = join(dir, "key.pem");
  assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", keyPath, "-out", certPath], { stdio: "ignore" }).status, 0);
  return { cert: await readFile(certPath), key: await readFile(keyPath), remove: () => rm(dir, { recursive: true, force: true }) };
}

// A TLS peer that answers each request head with the next scripted response bytes.
async function scriptedPeer(responses: (string | string[])[]) {
  const { cert, key, remove } = await localhostCertificate();
  const heads: string[] = [];
  let connections = 0;
  const sockets = new Set<TLSSocket>();
  const server = createTlsServer({ cert, key }, socket => {
    connections++;
    sockets.add(socket);
    socket.on("error", () => {});
    let buffered = "";
    socket.on("data", chunk => {
      buffered += chunk.toString("latin1");
      for (let end; (end = buffered.indexOf("\r\n\r\n")) >= 0;) {
        heads.push(buffered.slice(0, end));
        buffered = buffered.slice(end + 4);
        const response = responses.shift();
        if (response === undefined) continue;
        const parts = typeof response === "string" ? [response] : response;
        parts.forEach((part, index) => setTimeout(() => socket.write(part), index * 300));
      }
    });
  });
  // Bun reports failed handshakes only on the raw connection.
  const raw = new Set<import("node:net").Socket>();
  server.on("connection", socket => { raw.add(socket); socket.on("error", () => {}); });
  await new Promise<void>(done => server.listen(0, "localhost", done));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return {
    origin: `https://localhost:${address.port}`, cert, heads, connections: () => connections,
    close: async () => { for (const socket of [...sockets, ...raw]) socket.destroy(); await new Promise<void>(done => server.close(() => done())); await remove(); },
  };
}

test("NEAR direct evidence and inference stay on one authenticated socket, with approval before credentials", async () => {
  const { cert, key, remove } = await localhostCertificate();
  let sends = 0;
  let connections = 0;
  const server = createServer({ cert, key }, (req, res) => {
    sends++;
    req.resume();
    req.on("end", () => {
      if (req.url?.startsWith("/v1/signature/slow")) { res.writeHead(200); res.write("synthetic"); }
      else res.end("synthetic");
    });
  });
  server.on("connection", () => connections++);
  let channel: NearDirectChannel | undefined;
  try {
    await new Promise<void>(resolve => server.listen(0, "localhost", resolve));
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const origin = `https://localhost:${address.port}`;
    channel = new NearDirectChannel(origin, AbortSignal.timeout(10000), { ca: cert });
    const fetch = channel.fetch;
    const chat = new Request(`${origin}/ohttp`, { method: "POST", body: "synthetic", headers: { authorization: "Bearer synthetic" } });
    await assert.rejects(fetch(chat.clone()), /TEE_REQUEST_REJECTED/);
    assert.equal(sends, 0);
    const evidence = await channel.request(new Request(`${origin}${evidencePath}`));
    await evidence.response.text();
    assert.throws(() => channel!.approve("00".repeat(32)), /TEE_TLS_KEY_REJECTED/);
    await assert.rejects(fetch(chat.clone()), /TEE_REQUEST_REJECTED/);
    assert.equal(sends, 1);
    await assert.rejects(fetch(`${origin}/v1/attestation/report?nonce=bad&include_tls_fingerprint=true&signing_algo=ed25519`), /TEE_REQUEST_REJECTED/);
    channel.approve(evidence.peerSpkiFingerprint!);
    assert.equal(await (await fetch(chat.clone())).text(), "synthetic");
    assert.equal(await (await fetch(`${origin}/v1/signature/synthetic?signing_algo=ed25519`, { headers: { authorization: "Bearer synthetic" } })).text(), "synthetic");
    assert.equal(sends, 3);
    assert.equal(connections, 1);
    await assert.rejects(fetch(chat.clone()), /TEE_REQUEST_REJECTED/);
    await assert.rejects(fetch(`${origin}/outside`), /TEE_REQUEST_REJECTED/);
    channel.close();
    await assert.rejects(fetch(`${origin}${evidencePath}`), /TEE_TLS_KEY_REJECTED/);
    assert.equal(sends, 3);
    const cancellation = new AbortController();
    channel = new NearDirectChannel(origin, AbortSignal.any([cancellation.signal, AbortSignal.timeout(10000)]), { ca: cert });
    const nextEvidence = await channel.request(new Request(`${origin}${evidencePath}`));
    await nextEvidence.response.text();
    channel.approve(nextEvidence.peerSpkiFingerprint);
    const slow = await channel.fetch(`${origin}/v1/signature/slow`, { headers: { authorization: "Bearer synthetic" } });
    const reading = slow.text();
    cancellation.abort();
    await assert.rejects(reading);
    await assert.rejects(channel.fetch(chat.clone()));
    assert.equal(sends, 5, "Abort closes the stream without sending inference or reconnecting.");
  } finally {
    channel?.close();
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
    await remove();
  }
});

test("the NEAR gateway channel admits only its exchanges for one model, and inference only after approval", async () => {
  const { cert, key, remove } = await localhostCertificate();
  const paths: string[] = [];
  let connections = 0;
  const server = createServer({ cert, key }, (req, res) => { paths.push(`${req.method} ${req.url}`); req.resume(); req.on("end", () => res.end("synthetic")); });
  server.on("connection", () => connections++);
  const channels: NearDirectChannel[] = [];
  try {
    await new Promise<void>(resolve => server.listen(0, "localhost", resolve));
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const origin = `https://localhost:${address.port}`;
    const auth = { headers: { authorization: "Bearer synthetic" } };
    const nonce = "22".repeat(32);
    const metadata = `${origin}/v1/model/z-ai%2Fglm-5.3-flash`;
    const model = (name: string) => `${origin}/v1/attestation/report?model=${encodeURIComponent(name)}&provider=near&nonce=${nonce}&include_tls_fingerprint=false&signing_algo=ed25519`;
    const direct = new NearDirectChannel(origin, AbortSignal.timeout(10000), { ca: cert });
    channels.push(direct);
    await assert.rejects(direct.fetch(metadata), /TEE_REQUEST_REJECTED/, "Direct channels admit no gateway exchanges.");
    const channel = new NearDirectChannel(origin, AbortSignal.timeout(10000), { ca: cert }, { gatewayModel: "z-ai/glm-5.3-flash" });
    channels.push(channel);
    const chat = () => channel.fetch(`${origin}/ohttp`, { method: "POST", body: "synthetic", ...auth });
    await assert.rejects(chat(), /TEE_REQUEST_REJECTED/);
    // NEAR's gateway requires the API key for its own evidence; inference still waits for approval.
    const evidence = await channel.request(new Request(`${origin}${evidencePath}`, auth));
    await evidence.response.text();
    await (await channel.fetch(metadata, auth)).text();
    await (await channel.fetch(model("z-ai/glm-5.3-flash"), auth)).text();
    for (const outside of [`${origin}/v1/model/other`, model("other"), `${model("z-ai/glm-5.3-flash")}&signing_address=0x00`, `${origin}/v1/models`]) {
      await assert.rejects(channel.fetch(outside, auth), /TEE_REQUEST_REJECTED/, outside);
    }
    await assert.rejects(chat(), /TEE_REQUEST_REJECTED/);
    channel.approve(evidence.peerSpkiFingerprint);
    assert.equal(await (await chat()).text(), "synthetic");
    await assert.rejects(chat(), /TEE_REQUEST_REJECTED/);
    await (await channel.fetch(`${origin}/v1/signature/synthetic?signing_algo=ed25519`, auth)).text();
    assert.deepEqual(paths.map(path => path.split("?")[0]), ["GET /v1/attestation/report", "GET /v1/model/z-ai%2Fglm-5.3-flash", "GET /v1/attestation/report", "POST /ohttp", "GET /v1/signature/synthetic"]);
    assert.equal(connections, 1);
  } finally {
    for (const channel of channels) channel.close();
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
    await remove();
  }
});

test("a peer without WebPKI trust receives no HTTP and is never retried", async () => {
  const peer = await scriptedPeer(["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]);
  const channel = new NearDirectChannel(peer.origin, AbortSignal.timeout(10000));
  try {
    await assert.rejects(channel.request(new Request(`${peer.origin}${evidencePath}`)), /TEE_TLS_KEY_REJECTED/);
    await assert.rejects(channel.request(new Request(`${peer.origin}${evidencePath}`)), /TEE_TLS_KEY_REJECTED/);
    assert.equal(peer.heads.length, 0);
    assert.ok(peer.connections() <= 1);
  } finally { channel.close(); await peer.close(); }
});

test("requests take turns on the connection and the next is written only after the previous response ends", async () => {
  const peer = await scriptedPeer([
    ["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "5\r\nfirst\r\n0\r\n", "\r\n"],
    "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond",
    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nlast",
  ]);
  const channel = new NearDirectChannel(peer.origin, AbortSignal.timeout(10000), { ca: peer.cert });
  try {
    const first = await channel.request(new Request(`${peer.origin}${evidencePath}`));
    const second = channel.request(new Request(`${peer.origin}/v1/signature/synthetic`));
    // The peer has sent the last chunk but not the end of the trailer section.
    await new Promise(done => setTimeout(done, 450));
    assert.equal(peer.heads.length, 1, "No pipelining before the first response ends.");
    assert.equal(await first.response.text(), "first");
    assert.equal(await (await second).response.text(), "second");
    assert.equal(peer.heads.length, 2);
    assert.match(peer.heads[0]!, /^GET \/v1\/attestation\/report\?nonce=[0-9a-f]{64}&include_tls_fingerprint=true&signing_algo=ed25519 HTTP\/1\.1\r\n/);
    assert.match(peer.heads[0]!, /\r\nhost: localhost:[0-9]+(\r\n|$)/i);
    assert.equal((await channel.request(new Request(`${peer.origin}/v1/signature/synthetic`))).response.status, 200);
    await assert.rejects(channel.request(new Request(`${peer.origin}/v1/signature/synthetic`)), /TEE_TLS_KEY_REJECTED/);
    assert.equal(peer.heads.length, 3);
    assert.equal(peer.connections(), 1, "A closed connection is never replaced.");
  } finally { channel.close(); await peer.close(); }
});

test("unsolicited, malformed or unframed responses end the channel", async () => {
  for (const [name, response] of [
    ["bytes after the framed body", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA"],
    ["close-delimited body", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"],
    ["invalid header name", "HTTP/1.1 200 OK\r\nBad Name: x\r\nContent-Length: 2\r\n\r\nok"],
  ] as const) {
    const peer = await scriptedPeer([response, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]);
    const channel = new NearDirectChannel(peer.origin, AbortSignal.timeout(10000), { ca: peer.cert });
    try {
      await assert.rejects(async () => {
        await (await channel.request(new Request(`${peer.origin}${evidencePath}`))).response.text();
        await new Promise(done => setTimeout(done, 100));
        await channel.request(new Request(`${peer.origin}/v1/signature/synthetic`));
      }, /TEE_(RESPONSE|TLS_KEY)_REJECTED|TEE_CONNECTION_FAILED/, name);
      assert.equal(peer.heads.length, 1, name);
      assert.equal(peer.connections(), 1, name);
    } finally { channel.close(); await peer.close(); }
  }
});

test("both NEAR routes run under Node and Bun", () => {
  assert.doesNotThrow(() => assertNearRuntime());
});
