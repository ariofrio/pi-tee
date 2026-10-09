import { readFileSync } from "node:fs";
import { createServer } from "node:https";
import tls from "node:tls";
import { syncBuiltinESMExports } from "node:module";

const [certificate, privateKey, mode] = process.argv.slice(2);
let sends = 0, globalFetchCalls = 0, validSeal = false;
let dial: Record<string, unknown> | undefined;
const server = createServer({ cert: readFileSync(certificate!), key: readFileSync(privateKey!), minVersion: "TLSv1.3" }, (req, res) => {
  sends++;
  const chunks: Buffer[] = [];
  req.on("data", chunk => chunks.push(Buffer.from(chunk)));
  req.on("end", () => {
    validSeal = !!req.headers["ehbp-encapsulated-key"] && req.headers.authorization === "Bearer synthetic-key" &&
      req.headers["x-tinfoil-seal"] === "glm-5-3-inf18.tinfoil.containers.tinfoil.dev" &&
      !Buffer.concat(chunks).includes(Buffer.from("synthetic plaintext"));
    if (mode === "gateway" && !validSeal) {
      res.writeHead(500); res.end("bad seal");
    } else { res.writeHead(mode === "gateway" ? 412 : 200); res.end("ok"); }
  });
});
await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
const address = server.address();
if (!address || typeof address !== "object") throw new Error("Missing fixture port");
// Redirect only the external socket seam; retain production TLS options and endpoint.
if (mode === "gateway") {
  const connect = tls.connect;
  const redirected = ((options: tls.ConnectionOptions) => {
    dial = { host: options.host, port: options.port, servername: options.servername,
      rejectUnauthorized: options.rejectUnauthorized, minVersion: options.minVersion };
    return connect({ ...options, host: "127.0.0.1", port: address.port });
  }) as typeof tls.connect;
  tls.connect = redirected;
  if (process.versions.bun) {
    const moduleName = "bun:test";
    const { mock } = await import(moduleName);
    mock.module("node:tls", () => ({ ...tls, connect: redirected, default: tls }));
  } else syncBuiltinESMExports();
}
globalThis.fetch = async () => { globalFetchCalls++; return new Response("unexpected global fetch", { status: 412 }); };
let outcome = "accepted";
try {
  if (mode === "gateway") {
    const { Identity } = await import("ehbp");
    const { openEncryptedGatewayTransport } = await import("../../packages/tinfoil/src/direct.js");
    const worker = await Identity.generate();
    const transport = await openEncryptedGatewayTransport(AbortSignal.timeout(5000), "glm-5-3-inf18.tinfoil.containers.tinfoil.dev",
      { hpke: await worker.getPublicKeyHex() }, "glm-5-3", Date.now() + 60000);
    await transport.fetch(`${transport.baseUrl}/chat/completions`, {
      method: "POST", headers: { authorization: "Bearer synthetic-key" },
      body: JSON.stringify({ model: "glm-5-3", messages: [{ role: "user", content: "synthetic plaintext" }] }),
    });
  } else {
    const { webPkiTlsFetch } = await import("../../packages/core/src/pinned-tls.js");
    const endpoint = `https://localhost:${address.port}/v1/chat/completions`;
    await (await webPkiTlsFetch(endpoint)(endpoint, { method: "POST", body: "synthetic plaintext",
      headers: { authorization: "Bearer synthetic-key" }, signal: AbortSignal.timeout(5000) })).text();
  }
} catch (error) { outcome = String((error as Error).message); }
finally {
  server.closeAllConnections();
  await new Promise<void>(done => server.close(() => done()));
}
console.log(JSON.stringify({ outcome, sends, globalFetchCalls, validSeal, dial }));
