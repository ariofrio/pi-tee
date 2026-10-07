import assert from "node:assert/strict";
import { test } from "node:test";
import { resolvePolicy } from "../packages/core/src/policy.js";

test("an unconfigured provider requires independently approved workloads", () => {
  assert.equal(resolvePolicy(), "approved");
});

test("a misspelled security policy cannot silently select a weaker mode", () => {
  assert.throws(() => resolvePolicy("approve"), /TEE_POLICY_INVALID/);
});
