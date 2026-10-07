import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { qualifyIntelCandidate } from "../packages/tinfoil/src/intel-appraisal.js";

test("an unpinned local verifier cannot authorize an Intel worker or initiate attestation", async () => {
  await mkdir(".scratch/work", { recursive: true });
  const dir = await mkdtemp(resolve(".scratch/work/untrusted-verifier-"));
  let requests = 0;
  try {
    const cpuVerifier = resolve(dir, "verifier");
    await writeFile(cpuVerifier, "untrusted synthetic verifier", { mode: 0o700 });
    await assert.rejects(qualifyIntelCandidate({
      cpuVerifier, nvatDir: dir, signal: AbortSignal.timeout(5000),
      evidenceFetch: async () => { requests++; throw Error("must not fetch"); },
    }), /TEE_VERIFIER_ARTIFACT_REJECTED/);
    assert.equal(requests, 0);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("a direct encrypted worker error cannot resend credentials or ciphertext", async () => {
  const { createServer } = await import("node:https");
  const { spawnSync } = await import("node:child_process");
  const { createHash, X509Certificate } = await import("node:crypto");
  const { readFile } = await import("node:fs/promises");
  const { Identity } = await import("ehbp");
  const { openEncryptedWorkerTransport } = await import("../packages/tinfoil/src/direct.js");
  await mkdir(".scratch/work", { recursive: true });
  const dir = await mkdtemp(resolve(".scratch/work/send-once-"));
  const certPath = resolve(dir, "cert.pem");
  const keyPath = resolve(dir, "key.pem");
  assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=synthetic", "-keyout", keyPath, "-out", certPath], { stdio: "ignore" }).status, 0);
  const cert = await readFile(certPath);
  const fingerprint = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");
  const identity = await Identity.generate();
  let sends = 0;
  const server = createServer({ cert, key: await readFile(keyPath) }, (req, res) => {
    sends++;
    assert.equal(req.headers.authorization, "Bearer synthetic-key");
    const chunks: Buffer[] = [];
    req.on("data", chunk => chunks.push(chunk));
    req.on("end", () => {
      assert.ok(Buffer.concat(chunks).length > 0);
      assert.equal(Buffer.concat(chunks).includes(Buffer.from("synthetic plaintext")), false);
      res.writeHead(401); res.end("synthetic key rotation/error");
    });
  });
  try {
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const transport = await openEncryptedWorkerTransport(AbortSignal.timeout(10000), `127.0.0.1:${address.port}`, { tls: fingerprint, hpke: await identity.getPublicKeyHex() }, "cache_salt");
    const request = new Request(`${transport.baseUrl}/chat/completions`, { method: "POST", headers: { authorization: "Bearer synthetic-key", "content-type": "application/json" }, body: JSON.stringify({ messages: [{ role: "user", content: "synthetic plaintext" }] }) });
    await assert.rejects(transport.fetch(request.clone()), /TEE_RESPONSE_REJECTED/);
    assert.equal(sends, 1);
    await assert.rejects(transport.fetch(request.clone()), /TEE_REQUEST_REJECTED/);
    assert.equal(sends, 1, "An error/rotation response cannot authorize a second wire send.");
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
  }
});
