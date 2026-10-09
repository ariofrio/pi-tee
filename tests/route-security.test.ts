import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeContext, type Model } from "@earendil-works/pi-ai/compat";
import { createTeeProvider } from "../packages/core/src/provider.js";
import { assessRoute, compareRoutes, weakestRoute, type RouteSecurity } from "../packages/core/src/security.js";
import { parsePolicy } from "../packages/core/src/policy.js";

const direct: RouteSecurity = { route: "tinfoil-direct", provider: "Tinfoil", cpuVerified: true, code: 1, host: 1, gpu: 1, egress: 2, build: 3, review: 3, observed: [] };
const genoa = { ...direct, host: 2 as const };
const router: RouteSecurity = { route: "tinfoil-router", provider: "Tinfoil", cpuVerified: true, code: 3, host: 3, gpu: 3, egress: 3, observed: [] };
const near: RouteSecurity = { ...router, route: "near-direct", provider: "NEAR", host: 1 };
const gateway: RouteSecurity = { ...near, route: "near-gateway", host: 2 };

test("the tightest documented policies admit each route and reject weaker evidence", () => {
  for (const [route, policy] of [
    [direct, "public-builds,egress=metadata"],
    [genoa, "public-builds-trust-host,egress=metadata,host=outdated-firmware,gpu=verified"],
    [router, "trust-provider-and-host"],
    [near, "trust-provider-and-host,host=current"],
    [gateway, "trust-provider-and-host,host=outdated-firmware"],
  ] as const) assert.equal(assessRoute(parsePolicy(policy), route).accepted, true, route.route);
  assert.equal(assessRoute(parsePolicy(), genoa).accepted, false);
  assert.equal(assessRoute(parsePolicy("trust-provider"), near).accepted, false);
  assert.equal(assessRoute(parsePolicy("trust-provider-and-host,host=current"), gateway).accepted, false);
  assert.equal(assessRoute(parsePolicy("public-builds"), direct).accepted, false);
  assert.equal(assessRoute(parsePolicy("trust-provider-and-host"), { ...near, cpuVerified: false }).accepted, false);
});

test("code then host then gpu then egress breaks incomparable ties; weakest plaintext component counts", () => {
  assert.ok(compareRoutes(genoa, near) < 0);
  assert.ok(compareRoutes(near, gateway) < 0);
  assert.ok(compareRoutes({ ...direct, gpu: 2 }, { ...direct, gpu: 3, egress: 1 }) < 0);
  assert.ok(compareRoutes(direct, { ...direct, egress: 3 }) < 0);
  assert.equal(compareRoutes(direct, { ...direct, build: 4 }), 0);
  const path = weakestRoute("near-gateway", "NEAR", [near, gateway]);
  assert.equal(path.host, 2);
  assert.equal(path.gpu, 3);
  assert.equal(path.code, 3);
  assert.match(assessRoute(parsePolicy("trust-provider-and-host"), { ...gateway, observed: ["Intel OutOfDate", "Hopper PPCIe", "driver R570"] }).gaps.join(" "), /OutOfDate/);
});

test("native dispatch appraises qualifying routes and sends the prompt only to the strongest admitted route", async () => {
  const model: Model<"openai-completions"> = { id: "m", provider: "test", name: "M", api: "openai-completions", baseUrl: "https://test.example/v1", reasoning: false, input: ["text"], contextWindow: 8192, maxTokens: 512, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } };
  const sends: string[] = [], closed: string[] = [];
  const integration = createTeeProvider({
    id: "test", name: "Test", baseUrl: model.baseUrl, apiKeyEnv: "TEST_KEY", policy: "trust-provider-and-host",
    parseCatalog: () => [model], catalogFetch: async () => Response.json({}), assumptions: [],
    openSdkTransport: async () => { throw Error("unexpected legacy route"); },
    routes: [router, near, genoa].map(security => ({
      id: security.route, potential: security,
      openSession: async () => ({ security, transport: {
        dispose: () => { closed.push(security.route); },
        fetch: async () => { sends.push(security.route); return new Response('data: {"id":"c","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n', { headers: { "content-type": "text/event-stream" } }); },
      } }),
    })),
  });
  await integration.initializeCatalog();
  const result = await integration.provider.streamSimple(model, normalizeContext({ messages: [{ role: "user", content: "synthetic", timestamp: 1 }] }), { apiKey: "synthetic-key" }).result();
  assert.equal(result.stopReason, "stop");
  assert.deepEqual(sends, ["tinfoil-direct"]);
  assert.deepEqual(closed.sort(), ["near-direct", "tinfoil-direct", "tinfoil-router"]);
  assert.match(integration.getReport().routeDecisions!.find(r => r.picked)?.reason ?? "", /code/);
});
