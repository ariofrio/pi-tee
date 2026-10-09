import assert from "node:assert/strict";
import { test } from "node:test";
import { createCipheriv, hkdfSync, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Identity } from "ehbp";
import { CipherSuite, KDF_HKDF_SHA256, AEAD_AES_256_GCM } from "hpke";
import { KEM_DHKEM_X25519_HKDF_SHA256 } from "@panva/hpke-noble";
import { openEncryptedGatewayTransport } from "../packages/tinfoil/src/direct.js";
import { appraiseWorker } from "../packages/tinfoil/src/worker-appraisal.js";
import { parsePolicy, formatProviderReport } from "../packages/core/src/index.js";
import { createTinfoilProvider } from "../packages/tinfoil/src/index.js";
import { discoverGatewayWorkers, openRatedGatewayTransport } from "../packages/tinfoil/src/gateway.js";
import { verifyPublicBuildArtifacts } from "../packages/tinfoil/src/public-build.js";

const host = "glm-5-3-inf18.tinfoil.containers.tinfoil.dev";
const endpoint = "https://inference-gateway.tinfoil.sh/v1/chat/completions";
const suite = () => new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);

test("gateway sees metadata and ciphertext sealed to the appraised worker; 412 never loops", async () => {
  const worker = await Identity.generate();
  const wrongWorker = await Identity.generate();
  let sends = 0;
  const transport = await openEncryptedGatewayTransport(AbortSignal.timeout(10000), host, {
    hpke: await worker.getPublicKeyHex(),
  }, "glm-5-3", Date.now() + 60000, async (input, init) => {
    sends++;
    const request = new Request(input, init);
    assert.equal(request.url, endpoint);
    assert.equal(request.headers.get("authorization"), "Bearer synthetic-key");
    assert.equal(request.headers.get("x-tinfoil-seal"), host);
    assert.equal(request.headers.get("x-tinfoil-model"), "glm-5-3");
    const ciphertext = new Uint8Array(await request.arrayBuffer());
    assert.equal(Buffer.from(ciphertext).includes(Buffer.from("synthetic plaintext")), false);
    const enc = Buffer.from(request.headers.get("ehbp-encapsulated-key")!, "hex");
    const options = { info: new TextEncoder().encode("ehbp request") };
    const wrong = await suite().SetupRecipient(wrongWorker.getPrivateKey(), enc, options);
    await assert.rejects(wrong.Open(ciphertext.subarray(4)), "another worker cannot accept the body");
    const right = await suite().SetupRecipient(worker.getPrivateKey(), enc, options);
    const body = JSON.parse(new TextDecoder().decode(await right.Open(ciphertext.subarray(4))));
    assert.equal(body.messages[0].content, "synthetic plaintext");
    assert.match(body.cache_salt, /^[a-f0-9]{64}$/);
    return new Response("reroute", { status: 412, headers: { "x-tinfoil-seal": "glm-5-3-inf17.tinfoil.containers.tinfoil.dev" } });
  });
  const request = () => transport.fetch(`${transport.baseUrl}/chat/completions`, {
    method: "POST", headers: { authorization: "Bearer synthetic-key" },
    body: JSON.stringify({ model: "glm-5-3", messages: [{ role: "user", content: "synthetic plaintext" }] }),
  });
  await assert.rejects(request(), /TEE_RESPONSE_REJECTED/);
  await assert.rejects(request(), /TEE_REQUEST_REJECTED/);
  assert.equal(sends, 1);
});

test("gateway discovery cannot expand repositories, hosts or model coverage", async () => {
  const discover = (entry: unknown, model = "glm-5-3") => discoverGatewayWorkers(model, AbortSignal.timeout(5000), async input => {
    assert.equal(String(input), "https://inference-gateway.tinfoil.sh/catalog");
    return Response.json({ "glm-5-3": entry });
  });
  assert.deepEqual(await discover({ repo: "tinfoilsh/confidential-glm5-3-nvfp4", hosts: [host] }), [host]);
  for (const entry of [
    { repo: "tinfoilsh/other", hosts: [host] },
    { repo: "tinfoilsh/confidential-glm5-3-nvfp4", hosts: ["attacker.example"] },
    { repo: "tinfoilsh/confidential-glm5-3-nvfp4", hosts: [] },
    { repo: "tinfoilsh/confidential-glm5-3-nvfp4", hosts: Array(129).fill(host) },
  ]) await assert.rejects(discover(entry), /TEE_WORKER_DISCOVERY_UNAVAILABLE/);
  await assert.rejects(discover({}, "gemma4-31b"), /TEE_MODEL_UNAVAILABLE/);
});

test("relay appraisal sends a new nonce without credentials on every dispatch", async () => {
  const nonces = new Set<string>();
  for (let attempt = 0; attempt < 2; attempt++) {
    await assert.rejects(appraiseWorker({ model: "glm-5-3", host, signal: AbortSignal.timeout(30000),
      attestationRelay: "inference-gateway.tinfoil.sh",
      evidenceFetch: async (input, init) => {
        const request = new Request(input, init);
        const url = new URL(request.url);
        assert.equal(url.origin, "https://inference-gateway.tinfoil.sh");
        assert.equal(url.pathname, "/.well-known/tinfoil-attestation");
        assert.equal(url.searchParams.get("enclave"), host);
        const nonce = url.searchParams.get("nonce")!;
        assert.match(nonce, /^[a-f0-9]{64}$/);
        assert.equal(nonces.has(nonce), false);
        nonces.add(nonce);
        assert.equal(request.headers.has("authorization"), false);
        assert.equal(request.body, null);
        return Response.json({});
      },
    }), /TEE_PUBLIC_BUILD_REJECTED/);
  }
  assert.equal(nonces.size, 2);
});

test("gateway response substitution cannot expose unauthenticated text", async () => {
  const worker = await Identity.generate();
  for (const mode of ["valid", "plaintext", "empty", "wrong-nonce", "other-request", "tampered", "truncated"] as const) {
    const transport = await openEncryptedGatewayTransport(AbortSignal.timeout(10000), host, { hpke: await worker.getPublicKeyHex() }, "glm-5-3", Date.now() + 60000,
      async input => {
        const request = new Request(input);
        if (mode === "plaintext") return new Response("substituted text");
        if (mode === "empty") return new Response(null);
        let enc = Buffer.from(request.headers.get("ehbp-encapsulated-key")!, "hex");
        if (mode === "other-request") {
          const unrelated = await worker.encryptRequestWithContext(new Request(endpoint, { method: "POST", body: "different dispatch" }));
          enc = Buffer.from(unrelated.request.headers.get("ehbp-encapsulated-key")!, "hex");
        }
        const recipient = await suite().SetupRecipient(worker.getPrivateKey(), enc, { info: new TextEncoder().encode("ehbp request") });
        const exported = await recipient.Export(new TextEncoder().encode("ehbp response"), 32);
        const nonce = randomBytes(32);
        const salt = Buffer.concat([enc, nonce]);
        const key = hkdfSync("sha256", Buffer.from(exported), salt, "key", 32);
        const iv = hkdfSync("sha256", Buffer.from(exported), salt, "nonce", 12);
        const cipher = createCipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(iv));
        const ciphertext = Buffer.concat([cipher.update("authenticated worker text"), cipher.final(), cipher.getAuthTag()]);
        const frame = Buffer.alloc(4 + ciphertext.length);
        frame.writeUInt32BE(ciphertext.length); ciphertext.copy(frame, 4);
        if (mode === "tampered") frame[frame.length - 1] = frame[frame.length - 1]! ^ 1;
        if (mode === "wrong-nonce") nonce[0] = nonce[0]! ^ 1;
        return new Response(mode === "truncated" ? frame.subarray(0, -1) : frame, { headers: { "ehbp-response-nonce": nonce.toString("hex") } });
      });
    const consume = async () => (await transport.fetch(`${transport.baseUrl}/chat/completions`, {
      method: "POST", body: JSON.stringify({ model: "glm-5-3", messages: [] }),
    })).text();
    if (mode === "valid") assert.equal(await consume(), "authenticated worker text");
    else await assert.rejects(consume(), /TEE_RESPONSE_REJECTED|Decryption failed|truncated encrypted response chunk/, mode);
  }
});

(process.env.PI_TEE_GATEWAY_TEST_EVIDENCE ? test : test.skip)("relay rejects wrong nonce and swapped key evidence before artifact or inference traffic", async () => {
  const fixture = JSON.parse(await readFile(process.env.PI_TEE_GATEWAY_TEST_EVIDENCE!, "utf8"));
  const original = fixture.envelope ?? fixture;
  assert.equal(original.format, "https://tinfoil.sh/predicate/attestation/v3");
  let calls = 0;
  await assert.rejects(appraiseWorker({ model: "glm-5-3", host, signal: AbortSignal.timeout(30000), attestationRelay: "inference-gateway.tinfoil.sh",
    evidenceFetch: async () => {
      calls++;
      assert.equal(calls, 1, "Replayed evidence must not authorize further requests.");
      return Response.json(original);
    },
  }), /TEE_PUBLIC_BUILD_REJECTED/);
  assert.equal(calls, 1);
  const swapped = structuredClone(original);
  const keys = JSON.parse(Buffer.from(swapped.crypto_material, "base64").toString());
  keys.items.find((key: { id: string }) => key.id === "hpke").data = "00".repeat(32);
  swapped.crypto_material = Buffer.from(JSON.stringify(keys)).toString("base64");
  // Preserve the fixture's correct nonce to isolate section binding from replay rejection.
  await assert.rejects(verifyPublicBuildArtifacts({
    raw: JSON.stringify(swapped), nonce: original.challenge.nonce, repo: "tinfoilsh/confidential-glm5-3-nvfp4", signal: AbortSignal.timeout(30000),
    evidenceFetch: async () => { assert.fail("Swapped CPU-bound keys must not authorize artifact discovery."); },
  }), /TEE_PUBLIC_BUILD_REJECTED/);
});

test("gateway status discloses frame completeness and same-worker replay limits", () => {
  const status = formatProviderReport(createTinfoilProvider({ route: "gateway" }).getReport());
  assert.match(status, /frame boundary/);
  assert.match(status, /finish_reason/);
  assert.match(status, /usage/);
  assert.match(status, /replay.*same worker/);
  assert.match(status, /duplicate.*billing/);
});

test("production gateway selection uses the credential-free relay and caps each candidate at 120 seconds", async () => {
  const originalFetch = globalThis.fetch, originalTimeout = AbortSignal.timeout;
  const timeouts: number[] = [];
  let relays = 0;
  // Compress only the external clock; retain real discovery and worker appraisal.
  AbortSignal.timeout = milliseconds => {
    timeouts.push(milliseconds);
    return originalTimeout(milliseconds === 120000 ? 25 : 1000);
  };
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    assert.equal(url.origin, "https://inference-gateway.tinfoil.sh");
    assert.equal(request.headers.has("authorization"), false);
    assert.equal(request.body, null);
    if (url.pathname === "/catalog") return Response.json({ "glm-5-3": { repo: "tinfoilsh/confidential-glm5-3-nvfp4", hosts: [host] } });
    assert.equal(url.pathname, "/.well-known/tinfoil-attestation");
    assert.equal(url.searchParams.get("enclave"), host);
    assert.match(url.searchParams.get("nonce")!, /^[a-f0-9]{64}$/);
    relays++;
    return new Promise((_resolve, reject) => {
      const guard = setTimeout(() => reject(new Error("relay abort was not delivered")), 2000);
      const aborted = () => { clearTimeout(guard); reject(request.signal.reason); };
      if (request.signal.aborted) aborted();
      else request.signal.addEventListener("abort", aborted, { once: true });
    });
  };
  try {
    const started = performance.now();
    await assert.rejects(openRatedGatewayTransport(originalTimeout(5000), "glm-5-3", parsePolicy()), /TEE_/);
    assert.equal(relays, 1);
    assert.ok(timeouts.includes(120000), "Relay candidates must have the same 120s cap as direct.");
    assert.ok(performance.now() - started < 500, "The candidate cap must abort the relay fetch before its inner timeout.");
  } finally { globalThis.fetch = originalFetch; AbortSignal.timeout = originalTimeout; }
});
