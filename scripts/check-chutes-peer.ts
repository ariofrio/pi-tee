import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { createE2eeRequest, decryptE2eeStream } from "../packages/chutes/src/crypto.js";
import { acceptRequest, serverStream } from "../tests/chutes-crypto-fixture.js";

// Chutes' own browser test client is the conformance peer. The repository carries no
// license, so its artifacts are fetched by commit and hash rather than vendored.
const COMMIT = "0e3543180543c0c22637efb47a243d169ff0ab24";
const ARTIFACTS = {
  "chutes_e2ee_wasm.js": "98e68ccc42446e2a7051ecaa919e8d57a21c530cbf7e403af782a7864e404ad0",
  "chutes_e2ee_wasm_bg.wasm": "d1d9980cc56793cbb9c974c518c59601bac302e5cf6883c3d9a209db4c7de5c0",
};
type Peer = {
  initSync(options: { module: Uint8Array }): unknown;
  // serde-wasm-bindgen returns byte vectors as plain arrays.
  build_e2ee_request(publicKey: string, payload: string): { blob: number[]; response_sk: number[] };
  decrypt_stream_init(secret: Uint8Array, ct: string): Uint8Array;
  decrypt_stream_chunk(chunk: string, key: Uint8Array): string;
};

async function loadPeer(): Promise<Peer> {
  const signal = AbortSignal.timeout(60000);
  const files = Object.fromEntries(await Promise.all(Object.entries(ARTIFACTS).map(async ([name, digest]) => {
    const response = await fetch(`https://raw.githubusercontent.com/chutesai/e2ee-test/${COMMIT}/src/wasm/${name}`, { signal, redirect: "error" });
    assert.ok(response.ok, `${name}: HTTP ${response.status}`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    assert.equal(createHash("sha256").update(bytes).digest("hex"), digest, `${name} does not match its pin`);
    return [name, bytes] as const;
  })));
  const dir = await mkdtemp(join(tmpdir(), "pi-tee-chutes-peer-"));
  try {
    const glue = join(dir, "chutes_e2ee_wasm.js");
    await writeFile(glue, files["chutes_e2ee_wasm.js"]!);
    const peer = await import(pathToFileURL(glue).href) as Peer;
    peer.initSync({ module: files["chutes_e2ee_wasm_bg.wasm"]! });
    return peer;
  } finally { await rm(dir, { recursive: true, force: true }); }
}

const peer = await loadPeer();
const server = ml_kem768.keygen();
const serverKey = Buffer.from(server.publicKey).toString("base64");
const payload = { model: "synthetic/model", stream: true, messages: [{ role: "user", content: "synthetic peer prompt π" }], tools: [{ type: "function", function: { name: "lookup", parameters: { type: "object" } } }] };
const chunks = [
  'data: {"id":"c1","choices":[{"index":0,"delta":{"content":"hé"}}]}\n\n',
  'data: {"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"t","type":"function","function":{"name":"lookup","arguments":"{}"}}]}}]}\n\n',
  'data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
];
const events = async (response: Response) => (await response.text()).split("\n").filter(line => line.startsWith("data: {")).map(line => JSON.parse(line.slice(6)));

// 1. Both clients' request blobs open under the same server procedure to the same payload.
const ours = createE2eeRequest(serverKey, payload);
const built = peer.build_e2ee_request(serverKey, JSON.stringify(payload));
const theirs = { blob: Uint8Array.from(built.blob), response_sk: Uint8Array.from(built.response_sk) };
const openedOurs = acceptRequest(ours.body, server.secretKey);
const openedTheirs = acceptRequest(theirs.blob, server.secretKey);
for (const opened of [openedOurs, openedTheirs]) {
  const { e2e_response_pk, ...rest } = opened;
  assert.deepEqual(rest, payload);
  assert.equal(Buffer.from(e2e_response_pk, "base64").length, 1184);
}
assert.equal(ours.responseSecret.length, theirs.response_sk.length);

// 2. The reference client decrypts the stream sealed to pi-tee's response key, chunk for chunk.
const stream = await serverStream(openedOurs.e2e_response_pk, chunks).text();
const sealed = stream.split("\n").filter(line => line.startsWith("data: {")).map(line => JSON.parse(line.slice(6)));
const streamKey = peer.decrypt_stream_init(ours.responseSecret.slice(), sealed[0].e2e_init);
assert.deepEqual(sealed.slice(1).map(event => peer.decrypt_stream_chunk(event.e2e, streamKey)), chunks);
const tampered = Buffer.from(sealed[1].e2e, "base64"); tampered[tampered.length - 1]! ^= 1;
assert.throws(() => peer.decrypt_stream_chunk(tampered.toString("base64"), streamKey));
assert.deepEqual(await events(decryptE2eeStream(new Response(stream, { headers: { "content-type": "text/event-stream" } }), ours.responseSecret, AbortSignal.timeout(10000))),
  chunks.map(chunk => JSON.parse(chunk.slice(6))));

// 3. pi-tee decrypts the stream sealed to the reference client's response key.
const theirStream = serverStream(openedTheirs.e2e_response_pk, chunks);
assert.deepEqual(await events(decryptE2eeStream(theirStream, theirs.response_sk, AbortSignal.timeout(10000))), chunks.map(chunk => JSON.parse(chunk.slice(6))));

console.log(JSON.stringify({ peer: `chutesai/e2ee-test@${COMMIT}`, request: "equivalent", stream: "interoperable", runtime: process.versions.bun ? `bun ${process.versions.bun}` : `node ${process.versions.node}` }));
