import { spawnSync } from "node:child_process";
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

function key(secret: Uint8Array, ct: Uint8Array, info: string) { return Buffer.from(hkdfSync("sha256", secret, ct.subarray(0, 16), info, 32)); }
// The synthetic peer uses Node/OpenSSL even when the client runs under Bun.
function nativeAead(mode: "seal" | "open", k: Buffer, nonce: Buffer, body: Buffer): Buffer {
  if (!process.versions.bun) {
    if (mode === "seal") {
      const cipher = createCipheriv("chacha20-poly1305", k, nonce, { authTagLength: 16 });
      return Buffer.concat([cipher.update(body), cipher.final(), cipher.getAuthTag()]);
    }
    const decipher = createDecipheriv("chacha20-poly1305", k, nonce, { authTagLength: 16 });
    decipher.setAuthTag(body.subarray(-16));
    return Buffer.concat([decipher.update(body.subarray(0, -16)), decipher.final()]);
  }
  const result = spawnSync("node", ["--input-type=module", "-e", `
    import { readFileSync } from 'node:fs';
    import { createCipheriv, createDecipheriv } from 'node:crypto';
    const x=JSON.parse(readFileSync(0,'utf8'));
    const k=Buffer.from(x.key,'hex'), n=Buffer.from(x.nonce,'hex'), b=Buffer.from(x.body,'hex');
    let output;
    if(x.mode==='seal') { const c=createCipheriv('chacha20-poly1305',k,n,{authTagLength:16}); output=Buffer.concat([c.update(b),c.final(),c.getAuthTag()]); }
    else { const c=createDecipheriv('chacha20-poly1305',k,n,{authTagLength:16}); c.setAuthTag(b.subarray(-16)); output=Buffer.concat([c.update(b.subarray(0,-16)),c.final()]); }
    process.stdout.write(output.toString('hex'));
  `], { input: JSON.stringify({ mode, key: k.toString("hex"), nonce: nonce.toString("hex"), body: body.toString("hex") }), encoding: "utf8" });
  if (result.status !== 0) throw new Error("Synthetic Node/OpenSSL peer failed.");
  return Buffer.from(result.stdout, "hex");
}
function encrypt(k: Buffer, text: string) {
  const nonce = randomBytes(12);
  return Buffer.concat([nonce, nativeAead("seal", k, nonce, Buffer.from(text))]).toString("base64");
}

export function acceptRequest(blob: Uint8Array, serverSecret: Uint8Array) {
  const bytes = Buffer.from(blob);
  const ct = bytes.subarray(0, 1088);
  const k = key(ml_kem768.decapsulate(ct, serverSecret), ct, "e2e-req-v1");
  return JSON.parse(gunzipSync(nativeAead("open", k, bytes.subarray(1088, 1100), bytes.subarray(1100))).toString());
}

export function serverStream(responsePk: string, chunks: string[], fault?: "tag" | "replay" | "plain" | "truncated") {
  const exchange = ml_kem768.encapsulate(Buffer.from(responsePk, "base64"));
  const k = key(exchange.sharedSecret, exchange.cipherText, "e2e-stream-v1");
  const events = chunks.map(text => encrypt(k, text));
  if (fault === "tag") events[0] = Buffer.alloc(50).toString("base64");
  if (fault === "replay") events.splice(1, 0, events[0]!);
  return new Response(`data: ${JSON.stringify({ e2e_init: Buffer.from(exchange.cipherText).toString("base64") })}\n\n` +
    events.map(e2e => `data: ${JSON.stringify({ e2e })}\n\n`).join("") +
    (fault === "plain" ? 'data: {"choices":[{"delta":{"content":"injected"}}]}\n\n' : "") +
    (fault === "truncated" ? "" : "data: [DONE]\n\n"), { headers: { "content-type": "text/event-stream" } });
}

