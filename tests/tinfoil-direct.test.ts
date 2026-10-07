import assert from "node:assert/strict";
import { test } from "node:test";
import { openDirectTinfoilTransport, TINFOIL_DIRECT_PROFILE } from "../packages/tinfoil/src/direct.js";

test("a routing service cannot replace the direct worker or its pinned artifact", async () => {
  for (const replacement of [{ domain: "attacker.example" }, { digest: "00".repeat(32) }, { releaseTag: "v0.0.24" }]) {
    let requests = 0;
    await assert.rejects(openDirectTinfoilTransport(AbortSignal.timeout(10000), async (input, init) => {
      requests++;
      const request = new Request(input, init);
      assert.equal(request.url, "https://atc.tinfoil.sh/attestation");
      assert.equal(request.headers.has("authorization"), false);
      assert.deepEqual(await request.json(), { enclaveUrl: `https://${TINFOIL_DIRECT_PROFILE.host}`, repo: TINFOIL_DIRECT_PROFILE.repo });
      return Response.json({ domain: TINFOIL_DIRECT_PROFILE.host, digest: TINFOIL_DIRECT_PROFILE.digest, releaseTag: TINFOIL_DIRECT_PROFILE.tag, ...replacement });
    }), /TEE_WORKLOAD_PIN_REJECTED/);
    assert.equal(requests, 1, "Only metadata may be sent before all artifact pins pass.");
  }
});
