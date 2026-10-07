import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { createServer } from "node:https";
import { createServer as createTcpServer, type Socket } from "node:net";
import { createSecureContext } from "node:tls";
import { resolve, join } from "node:path";
import { pinnedTlsFetch } from "../packages/core/src/pinned-tls.js";

test("an attested TLS key authorizes the socket before any HTTP headers or body are sent", async () => {
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
  let delayHandshake = false;
  const server = createServer({ cert, key, SNICallback: (_name, callback) => {
    setTimeout(() => callback(null, createSecureContext({ cert, key })), delayHandshake ? 100 : 0);
  } }, (req, res) => {
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
    await assert.rejects(pinnedTlsFetch(endpoint, "00".repeat(32))(endpoint, options), /TEE_TLS_KEY_REJECTED/);
    assert.equal(sends, 0, "A mismatched key must receive neither credentials nor encrypted body.");
    const fingerprint = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");
    delayHandshake = true;
    await assert.rejects(pinnedTlsFetch(endpoint, fingerprint, Date.now() + 50)(endpoint, options), /TEE_PUBLIC_SESSION_REJECTED/);
    assert.equal(sends, 0, "Expiry during TLS setup must disclose neither credentials nor body.");
    delayHandshake = false;
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
