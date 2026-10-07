import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readBoundedBody } from "../../packages/core/src/transport.js";

// Test delivery seams only. NVIDIA's unchanged verifier must authenticate the
// exact reference/revocation bytes. No GPU report or credentials go upstream.
export async function collateralOracle(mode: "authentic" | "rim-signature" | "ocsp-signature") {
  let mutations = 0, deliveries = 0, failures = 0;
  const server = createServer((request, response) => {
    void (async () => {
      const signal = AbortSignal.timeout(15000);
      let bytes: Uint8Array;
      if (request.url === "/ocsp" && request.method === "POST") {
        const body: Buffer[] = [];
        let length = 0;
        for await (const chunk of request) {
          length += chunk.length;
          if (length > 65536) throw Error();
          body.push(chunk);
        }
        const upstream = await fetch("https://ocsp.ndis.nvidia.com", {
          method: "POST", headers: { "Content-Type": "application/ocsp-request", Accept: "application/ocsp-response" },
          body: Buffer.concat(body), signal, redirect: "error",
        });
        if (!upstream.ok) throw Error();
        bytes = await readBoundedBody(upstream.body, 65536, signal);
        if (mode === "ocsp-signature") { bytes = corruptOcspSignature(Buffer.from(bytes)); mutations++; }
        response.setHeader("Content-Type", "application/ocsp-response");
      } else if (request.method === "GET" && /^\/v1\/rim\/[A-Za-z0-9._-]{1,160}$/.test(request.url ?? "")) {
        const upstream = await fetch(`https://rim.attestation.nvidia.com${request.url}`, { signal, redirect: "error" });
        if (!upstream.ok) throw Error();
        bytes = await readBoundedBody(upstream.body, 16 * 1024 * 1024, signal);
        if (mode === "rim-signature") {
          const rim = JSON.parse(Buffer.from(bytes).toString("utf8"));
          let changed = false;
          const xml = Buffer.from(rim.rim, "base64").toString("utf8");
          const damaged = xml.replace(/(<(?:[A-Za-z_][A-Za-z0-9_.-]*:)?SignatureValue\b[^>]*>)([\s\S]*?)(<\/(?:[A-Za-z_][A-Za-z0-9_.-]*:)?SignatureValue>)/, (_match, start, value, end) => {
            const signature = Buffer.from(value.replace(/\s/g, ""), "base64");
            assert.ok(signature.length > 32);
            signature[signature.length - 1]! ^= 1; changed = true;
            return start + signature.toString("base64") + end;
          });
          assert.equal(changed, true);
          rim.rim = Buffer.from(damaged).toString("base64");
          bytes = Buffer.from(JSON.stringify(rim)); mutations++;
        }
        response.setHeader("Content-Type", "application/json");
      } else throw Error();
      deliveries++;
      response.writeHead(200); response.end(bytes);
    })().catch(() => { failures++; response.writeHead(502); response.end(); });
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const base = `http://127.0.0.1:${address.port}`;
  return {
    args: ["--rim-url", base, "--ocsp-url", `${base}/ocsp`],
    observations: () => ({ mutations, deliveries, failures }),
    async close() {
      server.closeAllConnections();
      await new Promise<void>(resolve => server.close(() => resolve()));
    },
  };
}

function corruptOcspSignature(bytes: Buffer): Buffer {
  // OCSPResponse.responseBytes.response contains BasicOCSPResponse, whose
  // third field is the signature BIT STRING. Preserve its DER and signed data.
  function tlv(offset: number, end = bytes.length) {
    assert.ok(offset >= 0 && offset + 2 <= end);
    const tag = bytes[offset++]!;
    let length = bytes[offset++]!;
    if (length & 0x80) {
      const count = length & 0x7f;
      assert.ok(count > 0 && count <= 4 && offset + count <= end);
      length = bytes.readUIntBE(offset, count); offset += count;
    }
    assert.ok(offset + length <= end);
    return { tag, start: offset, end: offset + length };
  }
  const outer = tlv(0); assert.equal(outer.tag, 0x30); assert.equal(outer.end, bytes.length);
  const status = tlv(outer.start, outer.end); assert.equal(status.tag, 0x0a);
  assert.equal(status.end - status.start, 1); assert.equal(bytes[status.start], 0);
  const wrapped = tlv(status.end, outer.end); assert.equal(wrapped.tag, 0xa0);
  const response = tlv(wrapped.start, wrapped.end); assert.equal(response.tag, 0x30);
  const type = tlv(response.start, response.end); assert.equal(type.tag, 6);
  const octets = tlv(type.end, response.end); assert.equal(octets.tag, 4);
  const basic = tlv(octets.start, octets.end); assert.equal(basic.tag, 0x30);
  const data = tlv(basic.start, basic.end); assert.equal(data.tag, 0x30);
  const algorithm = tlv(data.end, basic.end); assert.equal(algorithm.tag, 0x30);
  const signature = tlv(algorithm.end, basic.end); assert.equal(signature.tag, 3);
  assert.equal(bytes[signature.start], 0); assert.ok(signature.end - signature.start > 32);
  bytes[signature.end - 1]! ^= 1;
  return bytes;
}
