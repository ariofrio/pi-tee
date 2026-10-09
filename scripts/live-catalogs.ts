import assert from "node:assert/strict";
import { createNearProvider } from "../packages/nearai/src/index.js";
import { createTinfoilProvider } from "../packages/tinfoil/src/index.js";

const integrations = [createNearProvider({ policy: "trust-provider-and-host" }), createTinfoilProvider({ policy: "trust-provider-and-host" })];
const results = await Promise.allSettled(integrations.map(async (integration) => {
  await integration.initializeCatalog(AbortSignal.timeout(15_000));
  const report = integration.getReport();
  assert.ok(report.catalogModels > 0, `${report.provider} has a validated chat/tool catalog`);
  console.log(`${report.provider}: ${report.catalogModels} chat/tool models mapped; ${integration.provider.getModels().length} shown${report.declaredTeeModels === undefined ? "" : `, ${report.declaredTeeModels} declare model attestation`}. Metadata is a provider claim.`);
}));
for (const result of results) if (result.status === "rejected") throw result.reason;
