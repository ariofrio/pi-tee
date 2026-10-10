import assert from "node:assert/strict";
import { test } from "node:test";
import { formatProviderReport } from "../packages/core/src/status.js";
import { assessRoute } from "../packages/core/src/security.js";
import { parsePolicy } from "../packages/core/src/policy.js";

test("status explains the position, actual trusts, every gap and route choice", () => {
  const settings = parsePolicy("trust-provider-and-host,host=outdated-firmware");
  const route = assessRoute(settings, { route: "near-gateway", provider: "NEAR", cpuVerified: true, code: 3, host: 2, gpu: 3, egress: 3,
    observed: ["Intel OutOfDate", "Hopper PPCIe", "driver R570"] });
  const text = formatProviderReport({ provider: "nearai", policy: "trust-provider-and-host,host=outdated-firmware", settings,
    routeDecisions: [{ ...route, picked: true, reason: "Picked: only qualifying route" }], lastRequest: "sdk-accepted", catalogModels: 1,
    assumptions: [], independentApproval: "not-established", protectedSession: "not-established", closedTrustSet: "not-established", publicBuildVerification: "not-established" });
  for (const expected of ["trust-provider-and-host", "NEAR", "host", "A3", "H2", "G3", "X3", "Intel OutOfDate", "Hopper PPCIe", "R570", "Picked", "Physical attacks"])
    assert.ok(text.includes(expected), expected);
  const empty = formatProviderReport({ ...JSON.parse(JSON.stringify({ provider: "tinfoil", policy: "public-builds,egress=metadata", lastRequest: "not-run", catalogModels: 0, assumptions: [] })), settings: parsePolicy() });
  assert.ok(empty.includes("No request"));
  assert.ok(empty.includes("verifier=local, appraisal=per-request."));
});
