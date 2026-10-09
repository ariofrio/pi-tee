import assert from "node:assert/strict";
import { test } from "node:test";
import { createNearCpuVerifier } from "../packages/nearai/src/cpu.js";
import type { Collateral, VerifiedReport } from "@phala/dcap-qvl";

test("NEAR H1 needs freshly authenticated UpToDate evidence and both local numeric floors", async () => {
  for (const [svn, edition, status, expected] of [
    [[3, 1, 2], 20, "UpToDate", 1],
    [[4, 2, 3], 21, "UpToDate", 1],
    [[2, 1, 2], 20, "UpToDate", 2],
    [[3, 0, 2], 20, "UpToDate", 2],
    [[3, 1, 1], 20, "UpToDate", 2],
    [[3, 1, 2], 19, "UpToDate", 2],
    [undefined, 20, "UpToDate", 2],
    [[3, 1, 2], undefined, "UpToDate", 2],
    [[3, 1, 2], 20, "OutOfDate", 2],
  ] as const) {
    const ratings: number[] = [];
    const verifier = createNearCpuVerifier({
      onRating: rating => ratings.push(rating.host),
      collateral: async () => ({ tcb_info: JSON.stringify({ tcbEvaluationDataNumber: edition }), qe_identity: JSON.stringify({ tcbEvaluationDataNumber: 20 }) }) as Collateral,
      verify: () => ({ status, advisory_ids: [], report: { asTd10: () => ({
        teeTcbSvn: svn ? Uint8Array.from([...svn, ...Array(13).fill(0)]) : undefined,
        tdAttributes: new Uint8Array(8), reportData: new Uint8Array(64), mrConfigId: new Uint8Array(48), rtMr3: new Uint8Array(48),
      }) } }) as unknown as VerifiedReport,
    });
    await verifier("00");
    assert.deepEqual(ratings, [expected], `${svn}/${edition}/${status}`);
  }
});

test("a signature or collateral rejection cannot create a NEAR host rating", async () => {
  let rated = false;
  const verifier = createNearCpuVerifier({ onRating: () => { rated = true; }, collateral: async () => { throw Error("invalid collateral"); } });
  await assert.rejects(Promise.resolve(verifier("00")));
  assert.equal(rated, false);
});
