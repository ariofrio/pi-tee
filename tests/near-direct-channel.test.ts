import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { createServer } from "node:https";
import { join, resolve } from "node:path";
import { NearDirectChannel } from "../packages/nearai/src/direct-channel.js";

test("NEAR direct evidence and inference stay on one authenticated socket, with approval before credentials", async () => {
  await mkdir(".scratch/work", { recursive: true });
  const dir = await mkdtemp(resolve(".scratch/work/near-tls-"));
  const certPath = join(dir, "cert.pem");
  const keyPath = join(dir, "key.pem");
  assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", keyPath, "-out", certPath], { stdio: "ignore" }).status, 0);
  const cert = await readFile(certPath);
  let sends = 0;
  let connections = 0;
  const server = createServer({ cert, key: await readFile(keyPath) }, (req, res) => {
    sends++;
    req.resume();
    req.on("end", () => {
      if (req.url?.startsWith("/v1/signature/slow")) { res.writeHead(200); res.write("synthetic"); }
      else res.end("synthetic");
    });
  });
  server.on("secureConnection", () => connections++);
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
    const evidence = await channel.request(new Request(`${origin}/v1/attestation/report?nonce=${"11".repeat(32)}&include_tls_fingerprint=true&signing_algo=ed25519`));
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
    await assert.rejects(fetch(`${origin}/v1/attestation/report?nonce=${"11".repeat(32)}&include_tls_fingerprint=true&signing_algo=ed25519`), /TEE_TLS_KEY_REJECTED/);
    assert.equal(sends, 3);
    const cancellation = new AbortController();
    channel = new NearDirectChannel(origin, AbortSignal.any([cancellation.signal, AbortSignal.timeout(10000)]), { ca: cert });
    const nextEvidence = await channel.request(new Request(`${origin}/v1/attestation/report?nonce=${"11".repeat(32)}&include_tls_fingerprint=true&signing_algo=ed25519`));
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
    await rm(dir, { recursive: true, force: true });
  }
});
