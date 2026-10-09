import assert from "node:assert/strict";
import { test } from "node:test";
import { tdxMeetsFloors, snpMeetsFloors } from "../packages/core/src/cpu-floors.js";

test("authenticated TDX floor checks fail closed on absent, short and below-floor values", () => {
  assert.equal(tdxMeetsFloors(Uint8Array.from([3, 1, 2, ...Array(13).fill(0)]), [20, 21]), true);
  for (const [svn, editions] of [[undefined, [20, 20]], [new Uint8Array(15), [20, 20]], [new Uint8Array(16), [20, 20]], [Uint8Array.from([3, 1, 2, ...Array(13).fill(0)]), [19, 20]]] as const) assert.equal(tdxMeetsFloors(svn, editions), false);
});
test("authenticated SNP floors use CPUID, firmware build/API, both TCBs and released firmware", () => {
  const evidence = { cpu: "19/11/01", build: 21, api: [1, 55], provisional: false, current: [7, 0, 27, 86], launch: [7, 0, 27, 86] };
  assert.equal(snpMeetsFloors(evidence), true);
  for (const override of [{ cpu: "unknown" }, { build: 20 }, { api: [1, 54] }, { provisional: true }, { current: [7, 0, 26, 86] }, { launch: [7, 0, 27, 85] }]) assert.equal(snpMeetsFloors({ ...evidence, ...override }), false);
});
