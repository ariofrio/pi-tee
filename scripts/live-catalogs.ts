import assert from "node:assert/strict";
import { createNearProvider } from "../packages/nearai/src/index.js";
import { createTinfoilProvider } from "../packages/tinfoil/src/index.js";

const integrations = [createNearProvider({ policy: "sdk" }), createTinfoilProvider({ policy: "sdk" })];
const results = await Promise.allSettled(integrations.map(async (integration) => {
  await integration.initializeCatalog(AbortSignal.timeout(15_000));
  const report = integration.getReport();
  assert.ok(report.catalogModels > 0, `${report.provider} has a validated chat/tool catalog`);
  console.log(`${report.provider}: ${report.catalogModels} chat/tool models mapped; metadata is a provider claim.`);
}));
for (const result of results) if (result.status === "rejected") throw result.reason;
