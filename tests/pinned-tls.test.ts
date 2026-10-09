import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { createServer } from "node:https";
import { connect as connectTcp, createServer as createTcpServer, type Socket } from "node:net";
import { resolve, join } from "node:path";
import { pinnedTlsFetch, webPkiTlsFetch } from "../packages/core/src/pinned-tls.js";

test("an attested TLS key authorizes the socket before any HTTP headers or body are sent", { timeout: 60000 }, async () => {
  await mkdir(".scratch/work", { recursive: true });
  const dir = await mkdtemp(resolve(".scratch/work/tls-fixture-"));
  let sends = 0;
  const fixtureDir = process.env.PI_TEE_TLS_TEST_FIXTURE_DIR;
  const certificate = join(fixtureDir ?? dir, "cert.pem");
  const privateKey = join(fixtureDir ?? dir, "key.pem");
  if (!fixtureDir) {
    const generated = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=synthetic-fixture", "-keyout", privateKey, "-out", certificate], { stdio: "ignore" });
    assert.equal(generated.status, 0, "Generating the ephemeral TLS fixture requires openssl.");
  }
  const cert = await readFile(certificate);
  const key = await readFile(privateKey);
  const server = createServer({ cert, key }, (req, res) => {
    sends++;
    assert.equal(req.headers.authorization, "Bearer synthetic-key");
    req.resume();
    req.on("end", () => {
      res.writeHead(200);
      if (req.headers["x-synthetic-mode"] === "long-stream") {
        res.write("first");
        const timer = setTimeout(() => res.end("last"), 11000);
        res.on("close", () => clearTimeout(timer));
      } else res.end("ok");
    });
  });
  try {
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const endpoint = `https://localhost:${address.port}/v1/chat/completions`;
    const signal = AbortSignal.timeout(10000);
    const options = { method: "POST", body: "synthetic", headers: { authorization: "Bearer synthetic-key" }, signal };
    await assert.rejects(webPkiTlsFetch(endpoint)(endpoint, options), /TEE_CONNECTION_FAILED|TEE_TLS_KEY_REJECTED/);
    assert.equal(sends, 0, "An untrusted gateway certificate must receive neither credentials nor ciphertext.");
    // A relay that holds the server's first handshake bytes delays TLS setup on any runtime.
    const relays = new Set<Socket>();
    const relay = createTcpServer(client => {
      const upstream = connectTcp(address.port, "127.0.0.1");
      relays.add(client); relays.add(upstream);
      let first = true;
      upstream.on("data", chunk => {
        if (first) { first = false; upstream.pause(); setTimeout(() => { client.write(chunk); upstream.resume(); }, 100); }
        else client.write(chunk);
      });
      client.pipe(upstream);
      for (const socket of [client, upstream]) socket.on("error", () => {}).on("close", () => { client.destroy(); upstream.destroy(); });
    });
    await new Promise<void>(resolve => relay.listen(0, "127.0.0.1", resolve));
    const relayAddress = relay.address();
    assert.ok(relayAddress && typeof relayAddress === "object");
    const delayed = `https://localhost:${relayAddress.port}/v1/chat/completions`;
    await assert.rejects(pinnedTlsFetch(endpoint, "00".repeat(32))(endpoint, options), /TEE_TLS_KEY_REJECTED/);
    assert.equal(sends, 0, "A mismatched key must receive neither credentials nor encrypted body.");
    const fingerprint = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");
    await assert.rejects(pinnedTlsFetch(delayed, fingerprint, Date.now() + 50)(delayed, options), /TEE_PUBLIC_SESSION_REJECTED/);
    assert.equal(sends, 0, "Expiry during TLS setup must disclose neither credentials nor body.");
    for (const socket of relays) socket.destroy();
    await new Promise<void>(resolve => relay.close(() => resolve()));
    const response = await pinnedTlsFetch(endpoint, fingerprint, Date.now() + 10000)(endpoint, options);
    assert.equal(await response.text(), "ok");
    assert.equal(sends, 1);
    await assert.rejects(pinnedTlsFetch(endpoint, fingerprint)(endpoint + "?redirect", options), /TEE_REQUEST_REJECTED/);
    assert.equal(sends, 1);
    const stream = await pinnedTlsFetch(endpoint, fingerprint, Date.now() + 5000)(endpoint, {
      ...options, signal: AbortSignal.timeout(20000), headers: { ...options.headers, "x-synthetic-mode": "long-stream" },
    });
    assert.equal(await stream.text(), "firstlast", "The connection timer and admission deadline must not cut off an admitted response.");
    assert.equal(sends, 2);
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
  }
});

test("native transport bounds a stalled TLS handshake without sending HTTP", { timeout: 20000 }, async () => {
  const peers = new Set<Socket>();
  const server = createTcpServer(socket => {
    peers.add(socket);
    socket.on("close", () => peers.delete(socket));
    socket.resume(); // Receive ClientHello, but never respond to the handshake.
  });
  try {
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const endpoint = `https://127.0.0.1:${address.port}/v1/chat/completions`;
    await assert.rejects(pinnedTlsFetch(endpoint, "00".repeat(32))(endpoint, {
      method: "POST", body: "synthetic payload", headers: { authorization: "Bearer synthetic-key" }, signal: AbortSignal.timeout(15000),
    }), /TEE_CONNECTION_FAILED/);
  } finally {
    for (const peer of peers) peer.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

// A raw TLS peer holding the pinned key: only it can send these bytes, so the
// client must fail the request, never the process, and bound its own memory.
// The peer runs under Node for both runtimes (Bun's TLS server ignores maxVersion).
async function rawPeer(mode: "raw" | "flood", response = "", maxVersion = "TLSv1.3") {
  const { spawn } = await import("node:child_process");
  await mkdir(".scratch/work", { recursive: true });
  const dir = await mkdtemp(resolve(".scratch/work/tls-raw-"));
  const certificate = join(dir, "cert.pem"), privateKey = join(dir, "key.pem");
  const generated = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=synthetic-fixture", "-keyout", privateKey, "-out", certificate], { stdio: "ignore" });
  assert.equal(generated.status, 0, "Generating the ephemeral TLS fixture requires openssl.");
  const cert = await readFile(certificate);
  const child = spawn(process.versions.bun ? "node" : process.execPath,
    ["tests/fixtures/raw-tls-peer.mjs", certificate, privateKey, maxVersion, mode, Buffer.from(response).toString("base64")], { stdio: ["ignore", "pipe", "inherit"] });
  let written = 0;
  const port = await new Promise<number>((done, fail) => {
    let first = true;
    child.stdout!.setEncoding("utf8").on("data", (text: string) => {
      for (const line of text.split("\n").filter(Boolean)) {
        if (first) { first = false; done(Number(line)); }
        else if (line.startsWith("written ")) written = Number(line.slice(8));
      }
    });
    child.once("exit", () => fail(new Error("peer exited")));
  });
  const endpoint = `https://localhost:${port}/v1/chat/completions`;
  const fingerprint = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");
  const fetch = () => pinnedTlsFetch(endpoint, fingerprint)(endpoint, { method: "POST", body: "synthetic", signal: AbortSignal.timeout(10000) });
  return { fetch, written: () => written, close: async () => { child.kill(); await rm(dir, { recursive: true, force: true }); } };
}

test("malformed, unframed or downgraded responses from the pinned peer fail the request", { timeout: 60000 }, async () => {
  for (const [name, head] of [
    ["invalid header name", "HTTP/1.1 200 OK\r\nBad Name: x\r\nContent-Length: 2\r\n\r\nok"],
    ["bare LF in a value", "HTTP/1.1 200 OK\r\nX: a\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\nok"],
    ["NUL in a value", "HTTP/1.1 200 OK\r\nX: a\0b\r\nContent-Length: 2\r\n\r\nok"],
    ["close-delimited body", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"],
  ] as const) {
    const peer = await rawPeer("raw", head);
    try {
      await assert.rejects(async () => { await (await peer.fetch()).text(); }, /TEE_RESPONSE_REJECTED|TEE_CONNECTION_FAILED/, name);
    } finally { await peer.close(); }
  }
  const framed = await rawPeer("raw", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
  try {
    assert.equal(await (await framed.fetch()).text(), "ok", "A well-formed response is the positive control.");
  } finally { await framed.close(); }
  const legacy = await rawPeer("raw", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "TLSv1.2");
  try {
    await assert.rejects(legacy.fetch(), /TEE_TLS_KEY_REJECTED|TEE_CONNECTION_FAILED/, "TLS 1.2");
  } finally { await legacy.close(); }
});

test("a stalled consumer bounds what the pinned peer can make the client buffer", { timeout: 90000 }, async () => {
  const peer = await rawPeer("flood");
  try {
    const reader = (await peer.fetch()).body!.getReader();
    await reader.read();
    // Node pauses the socket; Bun keeps reading natively, so the client fails
    // the response once it exceeds the encrypted-response limit. Wait until
    // the peer's writes settle rather than sampling at fixed times.
    let previous = -1, settled = 0;
    for (let waited = 0; waited < 30000 && settled < 4; waited += 500) {
      await new Promise(done => setTimeout(done, 500));
      const now = peer.written();
      settled = now > 0 && now === previous ? settled + 1 : 0;
      previous = now;
    }
    assert(settled >= 4, `the peer kept writing while the consumer stalled: ${peer.written()} bytes`);
    assert(previous < 128 * 1024 * 1024, `the peer pushed ${previous} bytes while the consumer stalled`);
    try {
      while (!(await reader.read()).done) { /* drain what was buffered */ }
    } catch (error) {
      assert.match(String((error as Error).message ?? error), /TEE_RESPONSE_REJECTED/);
    }
  } finally { await peer.close(); }
});
