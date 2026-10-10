import assert from "node:assert/strict";
import { test } from "node:test";
import { appraiseWorker } from "../packages/tinfoil/src/worker-appraisal.js";
import { parsePolicy, TeeError } from "pi-tee-core";

test("unchecked GPUs skip verifier delivery; helper host floors still gate H2", async () => {
  for (const current of [false, true]) {
    let helperCalls = 0;
    const policy = parsePolicy(`public-builds-trust-host,egress=metadata,host=${current ? "current" : "outdated-firmware"},gpu=unchecked`);
    const fetch: typeof globalThis.fetch = async input => {
      assert.match(String(input), /^https:\/\/test-inf1\.tinfoil\.containers\.tinfoil\.dev\/\.well-known\/tinfoil-attestation\?nonce=[a-f0-9]{64}$/);
      return Response.json({ device_evidence: Buffer.from('{"items":[]}').toString("base64"), crypto_material: Buffer.from(JSON.stringify({ items: [
        { id: "tls", format: "https://tinfoil.sh/key/spki-fp-sha256/v1", data: "a".repeat(64) },
        { id: "hpke", format: "https://tinfoil.sh/key/x25519-hpke/v1", data: "b".repeat(64) },
      ] })).toString("base64") });
    };
    const request = appraiseWorker({ model: "gemma4-31b", host: "test-inf1.tinfoil.containers.tinfoil.dev", signal: AbortSignal.timeout(5000), policy, evidenceFetch: fetch,
      verifyArtifacts: async options => {
        helperCalls++; assert.equal(options.allowOutdated, !current);
        // External authenticated helper seam: deliberately return H2 even when disallowed.
        return { repo: options.repo, platform: "sev-snp", hostLevel: 2, runtimeConfig: { gpus: 8, configDigest: "config" }, containerBuild: { imageDigest: "image" },
          codeFreshness: new Date().toISOString(), platformFreshness: new Date().toISOString(), digest: "workload", platformDigest: "platform", cvmManifestDigest: "manifest" } as any;
      },
    });
    if (current) await assert.rejects(request, /TEE_CPU_POLICY_REJECTED/);
    else { const result = await request; assert.equal(result.security.host, 2); assert.equal(result.security.gpu, 3); assert.match(result.security.observed.join(" "), /not requested/); }
    assert.equal(helperCalls, 1);
  }
});

function gpuWorker(items: (nonce: string) => unknown[]) {
  const fetch: typeof globalThis.fetch = async input => {
    const nonce = new URL(String(input)).searchParams.get("nonce")!;
    return Response.json({ device_evidence: Buffer.from(JSON.stringify({ items: items(nonce) })).toString("base64"), crypto_material: Buffer.from(JSON.stringify({ items: [
      { id: "tls", format: "https://tinfoil.sh/key/spki-fp-sha256/v1", data: "a".repeat(64) },
      { id: "hpke", format: "https://tinfoil.sh/key/x25519-hpke/v1", data: "b".repeat(64) },
    ] })).toString("base64") });
  };
  return fetch;
}
const gpuItem = (nonce: string, index: number) => ({ id: `gpu${index}`, kind: "gpu", vendor: "nvidia", format: "https://tinfoil.sh/format/nvidia-gpu-evidence/v1", evidence: { arch: "BLACKWELL", nonce, evidence: "AA==" } });
const build = (repo: string, gpus: number) => ({ repo, platform: "tdx", hostLevel: 1, runtimeConfig: { gpus, configDigest: "config" }, containerBuild: { imageDigest: "image" },
  codeFreshness: new Date().toISOString(), platformFreshness: new Date().toISOString(), digest: "workload", platformDigest: "platform", cvmManifestDigest: "manifest" } as any);
const host = "test-inf1.tinfoil.containers.tinfoil.dev";

test("the local GPU verifier runs alongside the build chain, whose authenticated GPU count still gates its verdict", async () => {
  const events: string[] = [];
  let authenticate!: () => void;
  const authenticated = new Promise<void>(resolve => { authenticate = resolve; });
  const request = appraiseWorker({ model: "glm-5-3", host, signal: AbortSignal.timeout(5000), policy: parsePolicy("public-builds,egress=metadata"),
    evidenceFetch: gpuWorker(nonce => [gpuItem(nonce, 0), gpuItem(nonce, 1)]),
    verifyArtifacts: async options => { events.push("build started"); await authenticated; events.push("build authenticated"); return build(options.repo, 1); },
    verifyGpus: async options => { events.push(`gpus started: ${options.evidence.length}`); return { code: 0, stdout: "{}" }; },
  });
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.deepEqual(events, ["gpus started: 2", "build started"]);
  authenticate();
  await assert.rejects(request, /TEE_GPU_POLICY_REJECTED/);
  assert.deepEqual(events, ["gpus started: 2", "build started", "build authenticated"]);
});

test("a rejected build chain cancels the early GPU verifier and reports its own rejection", async () => {
  let cancelled = false;
  await assert.rejects(appraiseWorker({ model: "glm-5-3", host, signal: AbortSignal.timeout(5000), policy: parsePolicy("public-builds,egress=metadata"),
    evidenceFetch: gpuWorker(nonce => [gpuItem(nonce, 0)]),
    verifyArtifacts: async () => { await new Promise(resolve => setTimeout(resolve, 20)); throw new TeeError("TEE_PUBLIC_BUILD_REJECTED"); },
    verifyGpus: options => new Promise((_, reject) => options.signal.addEventListener("abort", () => { cancelled = true; reject(options.signal.reason); }, { once: true })),
  }), /TEE_PUBLIC_BUILD_REJECTED/);
  assert.equal(cancelled, true);
});

test("GPU evidence is not appraised early under another nonce, beyond eight GPUs or under the remote verifier", async () => {
  for (const [policy, items] of [
    ["public-builds,egress=metadata", (nonce: string) => [gpuItem(nonce, 0), gpuItem("0".repeat(64), 1)]],
    ["public-builds,egress=metadata", (nonce: string) => Array.from({ length: 9 }, (_, index) => gpuItem(nonce, index))],
    ["public-builds,egress=metadata,verifier=nras", (nonce: string) => [gpuItem(nonce, 0)]],
  ] as const) {
    let calls = 0;
    await assert.rejects(appraiseWorker({ model: "glm-5-3", host, signal: AbortSignal.timeout(5000), policy: parsePolicy(policy), evidenceFetch: gpuWorker(items),
      verifyArtifacts: async options => policy.includes("nras") ? Promise.reject(new TeeError("TEE_PUBLIC_BUILD_REJECTED")) : build(options.repo, 2),
      verifyGpus: async () => { calls++; return { code: 0, stdout: "{}" }; },
    }), policy.includes("nras") ? /TEE_PUBLIC_BUILD_REJECTED/ : /TEE_GPU_POLICY_REJECTED/);
    assert.equal(calls, 0, policy);
  }
});
