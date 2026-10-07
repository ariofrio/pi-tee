import assert from "node:assert/strict";
import { test } from "node:test";
import { discoverTinfoilWorkers } from "../packages/tinfoil/src/worker-discovery.js";

const model = "gemma4-31b", repository = "tinfoilsh/confidential-gemma4-31b";
const host = "gemma4-31b-inf8-0.tinfoil.containers.tinfoil.dev";
const document = (repo = repository, hostname = host) => ({ models: {
  [model]: { repo, tag: "v0.0.25", enclaves: { [hostname]: {
    predicate: { type: "https://tinfoil.sh/predicate/tdx-guest/v2" }, tls_key_fp: "untrusted", hpke_key: "untrusted",
  } } },
} });

test("public worker discovery preserves candidates without treating claimed keys as attestation", async () => {
  const calls: string[] = [];
  const candidates = await discoverTinfoilWorkers({ model, repository, signal: AbortSignal.timeout(3000), fetch: async (input, init) => {
    calls.push(String(input));
    assert.equal(new Headers(init?.headers).get("authorization"), null);
    assert.equal(init?.redirect, "error");
    return Response.json(document());
  } });
  assert.deepEqual(calls, ["https://inference.tinfoil.sh/.well-known/tinfoil-proxy"]);
  assert.deepEqual(candidates, [{ host, claimedTag: "v0.0.25" }]);
});

test("worker discovery rejects changed authorities, arbitrary hosts and malformed releases", async () => {
  for (const value of [document("attacker/workload"), document(repository, "127.0.0.1"), document(repository, "gemma4-31b-inf1.tinfoil.containers.tinfoil.dev.attacker.invalid"),
    { models: { [model]: { ...document().models[model], tag: "latest" } } },
    { models: { [model]: { ...document().models[model], enclaves: Object.fromEntries(Array.from({ length: 129 }, (_, i) =>
      [`gemma4-31b-inf${i}.tinfoil.containers.tinfoil.dev`, {}])) } } },
  ]) {
    let calls = 0;
    await assert.rejects(discoverTinfoilWorkers({ model, repository, signal: AbortSignal.timeout(3000), fetch: async () => {
      calls++; return Response.json(value);
    } }), /TEE_WORKER_DISCOVERY_UNAVAILABLE/);
    assert.equal(calls, 2, "Both fixed delivery services are tried; neither can authorize a different workload.");
  }
});

test("worker discovery falls back before inference and propagates cancellation", async () => {
  let calls = 0;
  const candidates = await discoverTinfoilWorkers({ model, repository, signal: AbortSignal.timeout(3000), fetch: async () => {
    return ++calls === 1 ? new Response(null, { status: 503 }) : Response.json(document());
  } });
  assert.equal(calls, 2); assert.equal(candidates[0]?.host, host);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(discoverTinfoilWorkers({ model, repository, signal: controller.signal, fetch: async () => {
    throw new Error("An aborted discovery must not contact delivery.");
  } }), { name: "AbortError" });
});


test("worker host aliases need not equal catalog model IDs", async () => {
  const candidates = await discoverTinfoilWorkers({ model: "glm-5-3-flash", repository: "tinfoilsh/confidential-glm5-3-flash",
    signal: AbortSignal.timeout(3000), fetch: async () => Response.json({ models: { "glm-5-3-flash": {
      repo: "tinfoilsh/confidential-glm5-3-flash", tag: "v0.0.8", enclaves: { "glm5-3-flash-inf15.tinfoil.containers.tinfoil.dev": {} },
    } } }),
  });
  assert.deepEqual(candidates, [{ host: "glm5-3-flash-inf15.tinfoil.containers.tinfoil.dev", claimedTag: "v0.0.8" }]);
});
