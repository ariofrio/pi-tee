import assert from "node:assert/strict";
import { test } from "node:test";
import { rateAuthenticatedTdxHost } from "../packages/core/src/tdx-host.js";

test("authenticated TDX host rating requires UpToDate, component SVN floors and both collateral floors", () => {
  const svn = Uint8Array.from([3, 1, 2, ...Array(13).fill(0)]);
  const collateral = { tcb_info: '{"tcbEvaluationDataNumber":20}', qe_identity: '{"tcbEvaluationDataNumber":20}' };
  assert.equal(rateAuthenticatedTdxHost("UpToDate", svn, collateral).host, 1);
  for (const [status, values, claims] of [
    ["OutOfDate", svn, collateral],
    ["UpToDate", Uint8Array.from([2, 1, 2, ...Array(13).fill(0)]), collateral],
    ["UpToDate", svn, { ...collateral, qe_identity: '{"tcbEvaluationDataNumber":19}' }],
    ["UpToDate", svn, { ...collateral, tcb_info: '{}'}],
    ["UpToDate", undefined, collateral],
  ] as const) assert.equal(rateAuthenticatedTdxHost(status, values, claims).host, 2);
});
