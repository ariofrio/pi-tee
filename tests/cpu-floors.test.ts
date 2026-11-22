import assert from "node:assert/strict";
import { test } from "node:test";
import { tdxMeetsFloors, snpMeetsFloors } from "../packages/core/src/cpu-floors.js";

test("authenticated TDX floor checks fail closed on absent, short and below-floor values", () => {
  assert.equal(tdxMeetsFloors(Uint8Array.from([3, 1, 2, ...Array(13).fill(0)]), [20, 21]), true);
  for (const [svn, editions] of [[undefined, [20, 20]], [new Uint8Array(15), [20, 20]], [new Uint8Array(16), [20, 20]], [Uint8Array.from([3, 1, 2, ...Array(13).fill(0)]), [19, 20]]] as const) assert.equal(tdxMeetsFloors(svn, editions), false);
});
test("authenticated SNP floors use CPUID, firmware build/API, both TCBs and released firmware", () => {
  const evidence = { cpu: "19/11/01", build: 4, api: [1, 58], provisional: false, current: [7, 0, 0x1e, 0x5b], launch: [7, 0, 0x1e, 0x5b] };
  assert.equal(snpMeetsFloors(evidence), true);
  for (const override of [{ cpu: "unknown" }, { build: 3 }, { api: [1, 57] }, { provisional: true }, { current: [7, 0, 0x1d, 0x5b] }, { launch: [7, 0, 0x1e, 0x5a] }]) assert.equal(snpMeetsFloors({ ...evidence, ...override }), false);
});
test("SNP floors follow AMD-SB-3059 (SNP SPL) and AMD-SB-3061 (microcode) per stepping", () => {
  const meets = (cpu: string, build: number, tcb: number[]) => snpMeetsFloors({ cpu, build, api: [1, 58], provisional: false, current: tcb, launch: tcb });
  assert.equal(meets("19/11/02", 4, [7, 0, 0x1e, 0x5b]), true);
  assert.equal(meets("19/11/02", 4, [7, 0, 0x1e, 0x5a]), false);
  assert.equal(meets("1a/02/01", 10, [1, 1, 0x08, 0x76, 1]), true);
  assert.equal(meets("1a/02/01", 10, [1, 1, 0x07, 0x76, 1]), false);
  assert.equal(meets("1a/02/01", 10, [1, 1, 0x08, 0x75, 1]), false);
  assert.equal(meets("1a/02/01", 9, [1, 1, 0x08, 0x76, 1]), false);
  // 2026-11-22 Privatemode Coordinator: SB-3059 firmware 1.58.4 (SNP 0x1e), pre-SB-3061 microcode 0x58.
  assert.equal(meets("19/11/01", 4, [12, 0, 30, 88]), false);
  // Pre-bulletin values that met the previous floors are now below them.
  assert.equal(snpMeetsFloors({ cpu: "19/11/01", build: 49, api: [1, 55], provisional: false, current: [10, 0, 0x1b, 0x58], launch: [10, 0, 0x1b, 0x58] }), false);
  assert.equal(meets("1a/02/01", 3, [3, 2, 0x05, 0x61, 1]), false);
});
