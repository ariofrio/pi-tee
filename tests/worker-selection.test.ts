import assert from "node:assert/strict";
import { test } from "node:test";
import { TeeError, parsePolicy } from "pi-tee-core";
import { selectPublicWorker } from "../packages/tinfoil/src/public-session.js";

const keys = (host: string, level: 1 | 2 = 1) => ({ tls: "a".repeat(64), hpke: "b".repeat(64), publicBuild: { host },
  security: { route: "tinfoil-direct", provider: "Tinfoil", cpuVerified: true, code: 1, host: level, gpu: 1, egress: 2, build: 3, review: 3, observed: [host] } } as any);

test("Genoa needs an H2 policy and current workers win when both qualify", async () => {
  const deps = { discover: async () => ["genoa", "tdx"], reachable: async (hosts: string[]) => hosts,
    appraise: async (_model: unknown, host: string) => keys(host, host === "genoa" ? 2 : 1) };
  const relaxed = parsePolicy("public-builds-trust-host,egress=metadata,host=outdated-firmware,gpu=verified");
  assert.equal((await selectPublicWorker("gemma4-31b", AbortSignal.timeout(5000), deps, relaxed)).host, "tdx");
  const genoaOnly = { ...deps, discover: async () => ["genoa"] };
  await assert.rejects(selectPublicWorker("gemma4-31b", AbortSignal.timeout(5000), genoaOnly, parsePolicy()), /TEE_POLICY_ROUTE_REJECTED/);
  assert.equal((await selectPublicWorker("gemma4-31b", AbortSignal.timeout(5000), genoaOnly, relaxed)).host, "genoa");
});

test("unreachable workers do not consume full appraisals", async () => {
  const hosts = Array.from({ length: 30 }, (_, index) => `h${index}`);
  const appraised: string[] = [];
  const selected = await selectPublicWorker("gemma4-31b", AbortSignal.timeout(5000), {
    discover: async () => hosts,
    reachable: async candidates => candidates.filter(host => host === "h27" || host === "h3"),
    appraise: async (_model, host) => { appraised.push(host); if (host === "h3") throw new TeeError("TEE_PUBLIC_BUILD_REJECTED"); return keys(host); },
  });
  assert.equal(selected.host, "h27");
  assert(appraised.every(host => host === "h3" || host === "h27"), "only reachable hosts are appraised");
});

test("verification failures are capped and reported in preference to unavailability", async () => {
  const appraised: string[] = [];
  await assert.rejects(selectPublicWorker("gemma4-31b", AbortSignal.timeout(5000), {
    discover: async () => Array.from({ length: 10 }, (_, index) => `h${index}`),
    reachable: async candidates => candidates,
    appraise: async (_model, host) => { appraised.push(host); throw new TeeError("TEE_CPU_POLICY_REJECTED"); },
  }), /TEE_CPU_POLICY_REJECTED/);
  assert.equal(appraised.length, 4);
  await assert.rejects(selectPublicWorker("gemma4-31b", AbortSignal.timeout(5000), {
    discover: async () => ["h0"], reachable: async () => [], appraise: async (_model, host) => keys(host),
  }), /TEE_PUBLIC_BUILD_DEPLOYMENT_UNAVAILABLE/);
});
