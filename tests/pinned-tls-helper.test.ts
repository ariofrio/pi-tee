import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash, X509Certificate } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { pinnedTlsHelperFetch } from "../packages/core/src/pinned-tls-helper.js";

const helperPath = process.env.PI_TEE_PINNED_TLS_TEST_HELPER;

test("portable helper authenticates before credentials, streams, refuses redirects and cancels", { skip: !helperPath }, async () => {
  if (process.env.PI_TEE_TEST_EXPECTED_ARCH) assert.equal(process.arch, process.env.PI_TEE_TEST_EXPECTED_ARCH, "Run the native target architecture, not an emulated client runtime.");
  await mkdir(".scratch/work", { recursive: true });
  const dir = await mkdtemp(resolve(".scratch/work/portable-tls-fixture-"));
  const fixtureDir = process.env.PI_TEE_TLS_TEST_FIXTURE_DIR;
  const certPath = resolve(fixtureDir ?? dir, "cert.pem"), keyPath = resolve(fixtureDir ?? dir, "key.pem");
  if (!fixtureDir) {
    const generated = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=synthetic-fixture", "-keyout", keyPath, "-out", certPath], { stdio: "ignore" });
    assert.equal(generated.status, 0);
  }
  const cert = await readFile(certPath);
  const pin = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");
  const artifact = { helperPath: helperPath!, sha256: createHash("sha256").update(await readFile(helperPath!)).digest("hex") };
  // Use the same Node TLS server for Node and Bun clients: Bun's emulated
  // https.Server does not report a peer cancellation on an idle response.
  const node = process.env.PI_TEE_PINNED_TLS_TEST_NODE ?? ("bun" in process.versions ? "node" : process.execPath);
  const server = spawn(node, [resolve("tests/fixtures/pinned-tls-server.mjs"), certPath, keyPath], { stdio: ["ignore", "pipe", "pipe"] });
  let sends = 0, port = 0, closed = false, pending = "";
  server.stdout.on("data", chunk => {
    pending += chunk;
    let index: number;
    while ((index = pending.indexOf("\n")) !== -1) {
      const event = JSON.parse(pending.slice(0, index)); pending = pending.slice(index + 1);
      if (event.port) port = event.port;
      if (event.request) sends = event.request;
      if (event.closed) closed = true;
    }
  });
  let diagnostics = "";
  server.stderr.on("data", value => { diagnostics += value; });
  async function waitFor(predicate: () => boolean) {
    const until = Date.now() + 3000;
    while (!predicate() && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 10));
    assert.ok(predicate(), `TLS fixture observation timed out: ${diagnostics}`);
  }
  try {
    await waitFor(() => port !== 0);
    const endpoint = `https://127.0.0.1:${port}/v1/chat/completions`;
    const request = { method: "POST", body: "synthetic payload", headers: { authorization: "Bearer synthetic-key" }, signal: AbortSignal.timeout(10000) };
    await assert.rejects(pinnedTlsHelperFetch(endpoint, "00".repeat(32), artifact)(endpoint, request), /TEE_TLS_KEY_REJECTED/);
    assert.equal(sends, 0);
    await assert.rejects(pinnedTlsHelperFetch(endpoint, pin, { ...artifact, sha256: "00".repeat(32) })(endpoint, request), /TEE_VERIFIER_ARTIFACT_REJECTED/);
    assert.equal(sends, 0);
    const fetch = pinnedTlsHelperFetch(endpoint, pin, artifact);
    assert.equal(await (await fetch(endpoint, request)).text(), "complete");
    await waitFor(() => sends === 1);
    assert.equal(sends, 1);
    await assert.rejects(fetch(endpoint + "?override", request), /TEE_REQUEST_REJECTED/);
    assert.equal(sends, 1);
    const redirect = await fetch(endpoint, { ...request, headers: { ...request.headers, "x-synthetic-mode": "redirect" } });
    assert.equal(redirect.status, 307); assert.equal(await redirect.text(), "redirect");
    await waitFor(() => sends === 2);
    assert.equal(sends, 2);
    await assert.rejects(fetch(endpoint, { ...request, headers: { ...request.headers, "x-synthetic-mode": "drop" } }), /TEE_CONNECTION_FAILED/);
    await waitFor(() => sends === 3);
    assert.equal(sends, 3, "A dropped response cannot reconnect or resend the consumed payload.");
    const controller = new AbortController();
    const response = await fetch(endpoint, { ...request, headers: { ...request.headers, "x-synthetic-mode": "stream" }, signal: controller.signal });
    const reader = response.body!.getReader();
    assert.equal(new TextDecoder().decode((await reader.read()).value), "first delta");
    controller.abort();
    await assert.rejects(reader.read());
    await waitFor(() => closed);
    assert.equal(sends, 4);
  } finally {
    const exit = new Promise<void>(resolve => server.once("close", () => resolve()));
    server.kill(); await exit;
    await rm(dir, { recursive: true, force: true });
  }
});
