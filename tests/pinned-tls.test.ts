import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { createServer } from "node:https";
import { resolve, join } from "node:path";
import { pinnedTlsFetch } from "../packages/core/src/pinned-tls.js";

test("an attested TLS key authorizes the socket before any HTTP headers or body are sent", async () => {
  await mkdir(".scratch/work", { recursive: true });
  const dir = await mkdtemp(resolve(".scratch/work/tls-fixture-"));
  let sends = 0;
  const certificate = join(dir, "cert.pem");
  const privateKey = join(dir, "key.pem");
  const generated = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=synthetic-fixture", "-keyout", privateKey, "-out", certificate], { stdio: "ignore" });
  assert.equal(generated.status, 0, "Generating the ephemeral TLS fixture requires openssl.");
  const cert = await readFile(certificate);
  const server = createServer({ cert, key: await readFile(privateKey) }, (req, res) => {
    sends++;
    assert.equal(req.headers.authorization, "Bearer synthetic-key");
    req.resume();
    req.on("end", () => { res.writeHead(200); res.end("ok"); });
  });
  try {
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const endpoint = `https://127.0.0.1:${address.port}/v1/chat/completions`;
    const signal = AbortSignal.timeout(10000);
    const options = { method: "POST", body: "synthetic", headers: { authorization: "Bearer synthetic-key" }, signal };
    await assert.rejects(pinnedTlsFetch(endpoint, "00".repeat(32))(endpoint, options), /TEE_TLS_KEY_REJECTED/);
    assert.equal(sends, 0, "A mismatched key must receive neither credentials nor encrypted body.");
    const fingerprint = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");
    const response = await pinnedTlsFetch(endpoint, fingerprint)(endpoint, options);
    assert.equal(await response.text(), "ok");
    assert.equal(sends, 1);
    await assert.rejects(pinnedTlsFetch(endpoint, fingerprint)(endpoint + "?redirect", options), /TEE_REQUEST_REJECTED/);
    assert.equal(sends, 1);
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
  }
});
