import assert from "node:assert/strict";
import { test } from "node:test";
import { createNearProvider } from "../packages/nearai/src/index.js";
import { createTinfoilProvider } from "../packages/tinfoil/src/index.js";

test("removed provider settings reject even empty values before any network or credential lookup", () => {
  for (const [factory, variables] of [[createNearProvider, ["PI_NEARAI_POLICY", "PI_NEARAI_ROUTE"]], [createTinfoilProvider, ["PI_TINFOIL_POLICY", "PI_TINFOIL_ROUTE"]]] as const) {
    for (const variable of variables) for (const value of ["", "sdk", "direct"]) {
      const old = process.env[variable]; process.env[variable] = value;
      try { assert.throws(() => factory({ catalogFetch: async () => { throw Error("network must not open"); } }), error => {
        assert.equal((error as { code: string }).code, "TEE_POLICY_INVALID"); assert.match((error as Error).message, new RegExp(variable + " was removed; use PI_TEE_POLICY")); return true;
      }); }
      finally { if (old === undefined) delete process.env[variable]; else process.env[variable] = old; }
    }
  }
});
