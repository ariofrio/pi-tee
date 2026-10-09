import assert from "node:assert/strict";
import { test } from "node:test";
import { appraiseWorker } from "../packages/tinfoil/src/worker-appraisal.js";
import { parsePolicy } from "pi-tee-core";

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
