import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { qualifyIntelCandidate } from "../packages/tinfoil/src/intel-appraisal.js";
import { createTinfoilProvider, TINFOIL_ASSUMPTIONS } from "../packages/tinfoil/src/index.js";
import { normalizeContext } from "@earendil-works/pi-ai/compat";

test("an unqualified GPU verifier cannot collect evidence or release endpoint keys", { skip: !process.env.PI_TEE_PUBLIC_BUILD_TEST_HELPER || !process.env.PI_TEE_PUBLIC_BUILD_TEST_NVAT }, async () => {
  let metadataRequests = 0;
  await assert.rejects(qualifyIntelCandidate({
    cpuVerifier: process.env.PI_TEE_PUBLIC_BUILD_TEST_HELPER!, nvatDir: process.env.PI_TEE_PUBLIC_BUILD_TEST_NVAT!,
    mode: "public-builds", signal: AbortSignal.timeout(10000),
    evidenceFetch: async (input, options) => {
      metadataRequests++;
      assert.equal(metadataRequests, 1, "Invalid CPU evidence cannot authorize further discovery.");
      assert.match(String(input), /^https:\/\/gemma4-31b-inf8-0\.tinfoil\.containers\.tinfoil\.dev\/\.well-known\/tinfoil-attestation\?nonce=[a-f0-9]{64}$/);
      assert.equal(options?.headers, undefined);
      assert.equal(options?.body, undefined);
      return Response.json({});
    },
  }), /TEE_GPU_VERIFIER_UNQUALIFIED/);
  assert.equal(metadataRequests, 0);
});

test("default public admission remains gated and stale selections cannot fall back to SDK", async () => {
  await mkdir(".scratch/work", { recursive: true });
  const dir = await mkdtemp(resolve(".scratch/work/untrusted-public-verifier-"));
  const oldVerifier = process.env.PI_TINFOIL_PUBLIC_BUILD_VERIFIER;
  const oldNvat = process.env.PI_TINFOIL_NVAT_DIR;
  const oldRoute = process.env.PI_TINFOIL_ROUTE;
  const oldPolicy = process.env.PI_TINFOIL_POLICY;
  try {
    const path = resolve(dir, "verifier");
    await writeFile(path, "untrusted public-build verifier", { mode: 0o700 });
    process.env.PI_TINFOIL_PUBLIC_BUILD_VERIFIER = path;
    process.env.PI_TINFOIL_NVAT_DIR = dir;
    delete process.env.PI_TINFOIL_ROUTE;
    delete process.env.PI_TINFOIL_POLICY;
    for (const route of [undefined, "direct-public"] as const) {
      let sdkOpened = 0;
      const integration = createTinfoilProvider({ route, openSdkTransport: async () => { sdkOpened++; throw Error("must not open SDK"); },
        catalogFetch: async () => Response.json({ data: ["gemma4-31b", "gpt-oss-120b"].map(id => ({
          id, type: "chat", tool_calling: true, endpoints: ["/v1/chat/completions"], context_window: 131072,
          pricing: { inputTokenPricePer1M: 1, outputTokenPricePer1M: 2 },
        })) }),
      });
      await integration.initializeCatalog();
      assert.equal(integration.getReport().policy, "public-builds");
      assert.deepEqual(integration.provider.getModels().map(m => m.id), []);
      integration.setPolicy("sdk");
      const model = integration.provider.getModels()[0];
      integration.setPolicy("public-builds");
      assert.ok(model);
      const result = await integration.provider.streamSimple(model, normalizeContext({ messages: [{ role: "user", content: "synthetic prompt", timestamp: 1 }] }), { apiKey: "synthetic-key", maxRetries: 10 }).result();
      assert.equal(result.errorMessage, "TEE_PUBLIC_BUILD_DEPLOYMENT_UNAVAILABLE");
      assert.equal(sdkOpened, 0);
      assert.equal(integration.getReport().publicBuildVerification, "not-established");
      integration.setPolicy("approved");
      assert.equal(integration.provider.getModels().length, 0);
      integration.setPolicy("sdk");
      assert.deepEqual(integration.provider.getModels().map(m => m.id), route ? ["gemma4-31b"] : ["gemma4-31b", "gpt-oss-120b"]);
      if (route === undefined) assert.deepEqual(integration.getReport().assumptions, TINFOIL_ASSUMPTIONS);
      else assert.match(integration.getReport().assumptions[0]!, /^Experimental SDK-policy candidate:/);
    }
  } finally {
    for (const [name, value] of [["PI_TINFOIL_PUBLIC_BUILD_VERIFIER", oldVerifier], ["PI_TINFOIL_NVAT_DIR", oldNvat], ["PI_TINFOIL_ROUTE", oldRoute], ["PI_TINFOIL_POLICY", oldPolicy]]) {
      if (value === undefined) delete process.env[name!]; else process.env[name!] = value;
    }
    await rm(dir, { recursive: true, force: true });
  }
});

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


test("auto preserves SDK discovery while explicit router cannot admit public workloads", async () => {
  const catalogFetch: typeof fetch = async () => Response.json({ data: ["gemma4-31b", "gpt-oss-120b"].map(id => ({
    id, type: "chat", tool_calling: true, endpoints: ["/v1/chat/completions"], context_window: 131072,
    pricing: { inputTokenPricePer1M: 1, outputTokenPricePer1M: 2 },
  })) });
  const auto = createTinfoilProvider({ route: "auto", policy: "sdk", catalogFetch });
  await auto.initializeCatalog();
  assert.deepEqual(auto.provider.getModels().map(m => m.id), ["gemma4-31b", "gpt-oss-120b"]);
  let sdkOpened = 0;
  const router = createTinfoilProvider({ route: "router", policy: "sdk", catalogFetch,
    openSdkTransport: async () => { sdkOpened++; throw Error("must not open"); },
  });
  await router.initializeCatalog();
  const model = router.provider.getModels()[0];
  assert.ok(model);
  router.setPolicy("public-builds");
  assert.equal(router.provider.getModels().length, 0);
  const result = await router.provider.streamSimple(model, normalizeContext({ messages: [{ role: "user", content: "synthetic prompt", timestamp: 1 }] }), { apiKey: "synthetic-key" }).result();
  assert.equal(result.errorMessage, "TEE_PUBLIC_BUILD_DEPLOYMENT_UNAVAILABLE");
  assert.equal(sdkOpened, 0);
});
