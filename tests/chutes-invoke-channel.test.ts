import assert from "node:assert/strict";
import { test } from "node:test";
import { execFile, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:https";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

test("Chutes' invocation channel sends once even when the API returns HTTP 421", async () => {
  await mkdir(".scratch/work", { recursive: true });
  const dir = await mkdtemp(resolve(".scratch/work/chutes-invoke-"));
  const certPath = join(dir, "cert.pem"), keyPath = join(dir, "key.pem");
  assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", keyPath, "-out", certPath], { stdio: "ignore" }).status, 0);
  let sends = 0;
  const server = createServer({ cert: await readFile(certPath), key: await readFile(keyPath) }, (request, response) => {
    sends++;
    request.resume();
    request.on("end", () => { response.writeHead(421); response.end(); });
  });
  try {
    await new Promise<void>(done => server.listen(0, "localhost", done));
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const endpoint = `https://localhost:${address.port}/e2e/invoke`;
    const script = join(dir, "client.mjs");
    await writeFile(script, `
      import assert from 'node:assert/strict';
      import { chutesInvocationFetch } from ${JSON.stringify(resolve("packages/chutes/src/transport.ts"))};
      const endpoint = ${JSON.stringify(endpoint)};
      const response = await chutesInvocationFetch(endpoint, Date.now()+10000)(endpoint, {
        method:'POST', body:'synthetic-ciphertext', signal:AbortSignal.timeout(10000), redirect:'error',
        headers:{authorization:'Bearer synthetic-key'},
      });
      assert.equal(response.status,421); await response.arrayBuffer();
    `);
    await promisify(execFile)(process.execPath, [...(process.versions.bun ? [] : ["--import", "tsx"]), script], { env: { ...process.env, NODE_EXTRA_CA_CERTS: certPath } });
    assert.equal(sends, 1, "The invocation token and ciphertext must never be replayed.");
  } finally {
    server.closeAllConnections();
    await new Promise<void>(done => server.close(() => done()));
    await rm(dir, { recursive: true, force: true });
  }
});
