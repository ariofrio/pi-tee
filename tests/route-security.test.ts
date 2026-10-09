import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeContext, type Model } from "@earendil-works/pi-ai/compat";
import { createTeeProvider } from "../packages/core/src/provider.js";
import { RouteRejection, assessRoute, compareRoutes, weakestRoute, type RouteSecurity } from "../packages/core/src/security.js";
import { parsePolicy } from "../packages/core/src/policy.js";
import { TeeError } from "../packages/core/src/policy.js";

const model: Model<"openai-completions"> = { id: "m", provider: "test", name: "M", api: "openai-completions", baseUrl: "https://test.example/v1", reasoning: false, input: ["text"], contextWindow: 8192, maxTokens: 512, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } };

const direct: RouteSecurity = { route: "tinfoil-direct", provider: "Tinfoil", cpuVerified: true, code: 1, host: 1, gpu: 1, egress: 2, build: 3, review: 3, observed: [] };
const genoa = { ...direct, host: 2 as const };
const router: RouteSecurity = { route: "tinfoil-router", provider: "Tinfoil", cpuVerified: true, code: 3, host: 3, gpu: 3, egress: 3, observed: [] };
const near: RouteSecurity = { ...router, route: "near-direct", provider: "NEAR", host: 1 };
const gateway: RouteSecurity = { ...near, route: "near-gateway", host: 2 };

test("an equal-level Tinfoil gateway is used only when no direct worker qualifies", async () => {
  const model: Model<"openai-completions"> = { id: "m", provider: "test", name: "M", api: "openai-completions", baseUrl: "https://test.example/v1", reasoning: false, input: ["text"], contextWindow: 8192, maxTokens: 512, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } };
  for (const directAvailable of [true, false]) {
    const opened: string[] = [], sent: string[] = [];
    const integration = createTeeProvider({ id: "test", name: "Test", baseUrl: model.baseUrl, apiKeyEnv: "TEST_KEY", policy: "public-builds,egress=metadata",
      parseCatalog: () => [model], catalogFetch: async () => Response.json({}), assumptions: [], openSdkTransport: async () => { throw Error(); },
      routes: [direct, { ...direct, route: "tinfoil-gateway" }].map(security => ({
        id: security.route, potential: security,
        ...(security.route === "tinfoil-gateway" ? { fallbackFor: "tinfoil-direct", preferenceReason: "Direct exposes the API key and metadata to fewer parties." } : {}),
        openSession: async () => {
          opened.push(security.route);
          if (security.route === "tinfoil-direct" && !directAvailable) throw new TeeError("TEE_PUBLIC_BUILD_DEPLOYMENT_UNAVAILABLE");
          return { security, transport: { fetch: async () => {
            sent.push(security.route);
            return new Response('data: {"id":"c","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n', { headers: { "content-type": "text/event-stream" } });
          } } };
        },
      })),
    });
    await integration.initializeCatalog();
    const result = await integration.provider.streamSimple(model, normalizeContext({ messages: [{ role: "user", content: "synthetic", timestamp: 1 }] }), { apiKey: "synthetic-key" }).result();
    assert.equal(result.stopReason, "stop");
    assert.deepEqual(sent, [directAvailable ? "tinfoil-direct" : "tinfoil-gateway"]);
    assert.equal(opened.includes("tinfoil-gateway"), !directAvailable);
    if (directAvailable) assert.match(integration.getReport().routeDecisions!.find(r => r.route === "tinfoil-gateway")!.reason, /fewer parties/);
  }
});

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

test("an expired rated session cannot send a prompt", async () => {
  let sent = false;
  const model: Model<"openai-completions"> = { id: "m", provider: "test", name: "M", api: "openai-completions", baseUrl: "https://test.example/v1", reasoning: false, input: ["text"], contextWindow: 8192, maxTokens: 512, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } };
  const integration = createTeeProvider({ id: "test", name: "Test", baseUrl: model.baseUrl, apiKeyEnv: "TEST_KEY", policy: "trust-provider-and-host",
    parseCatalog: () => [model], catalogFetch: async () => Response.json({}), assumptions: [], openSdkTransport: async () => { throw Error(); },
    routes: [{ id: near.route, potential: near, openSession: async () => ({ security: near, transport: { expiresAt: Date.now() - 1,
      fetch: async () => { sent = true; throw Error(); } } }) }],
  });
  await integration.initializeCatalog();
  const result = await integration.provider.streamSimple(model, normalizeContext({ messages: [{ role: "user", content: "synthetic", timestamp: 1 }] }), { apiKey: "synthetic-key" }).result();
  assert.equal(sent, false);
  assert.equal(result.errorMessage, "TEE_PUBLIC_SESSION_REJECTED");
});

test("unrated legacy SDK dispatch cannot bypass either provider-trusting position", async () => {
  for (const policy of ["trust-provider", "trust-provider-and-host"]) {
    let opened = 0;
    const integration = createTeeProvider({ id: "test", name: "Test", baseUrl: model.baseUrl, apiKeyEnv: "TEST_KEY", policy,
      parseCatalog: () => [model], catalogFetch: async () => Response.json({}), assumptions: [],
      openSdkTransport: async () => { opened++; return { fetch: async () => { throw Error("unrated dispatch"); } }; },
    });
    await integration.initializeCatalog();
    const result = await integration.provider.streamSimple(model, normalizeContext({ messages: [{ role: "user", content: "synthetic", timestamp: 1 }] }), { apiKey: "synthetic-key" }).result();
    assert.equal(opened, 0);
    assert.equal(result.errorMessage, "TEE_POLICY_ROUTE_REJECTED");
  }
});

test("inconsistent or malformed actual levels fail closed", () => {
  for (const changed of [ { host: 3, gpu: 1 }, { code: 3, egress: 2 }, { host: 0 }, { gpu: 4 }, { code: 1.5 }, { egress: NaN }, { build: undefined } ]) {
    assert.equal(assessRoute(parsePolicy(), { ...direct, ...changed } as RouteSecurity).accepted, false);
  }
});

test("a mismatched route identity cannot dispatch even when its levels qualify", async () => {
  let sends = 0, disposed = 0;
  const integration = createTeeProvider({ id: "test", name: "Test", baseUrl: model.baseUrl, apiKeyEnv: "TEST_KEY", policy: "trust-provider-and-host",
    parseCatalog: () => [model], catalogFetch: async () => Response.json({}), assumptions: [], openSdkTransport: async () => { throw Error(); },
    routes: [{ id: router.route, potential: router, openSession: async () => ({ security: { ...router, route: "other" }, transport: { dispose: () => { disposed++; }, fetch: async () => { sends++; throw Error(); } } }) }],
  });
  await integration.initializeCatalog();
  const result = await integration.provider.streamSimple(model, normalizeContext({ messages: [{ role: "user", content: "synthetic", timestamp: 1 }] }), { apiKey: "synthetic-key" }).result();
  assert.equal(sends, 0); assert.equal(disposed, 1); assert.equal(result.errorMessage, "TEE_POLICY_ROUTE_REJECTED");
  assert.match(integration.getReport().routeDecisions![0]!.reason, /different route identity/);
});


test("authenticated rejected worker levels disclose the failing axis through native dispatch", async () => {
  for (const changed of [{ host: 2 as const }, { gpu: 2 as const }]) {
    let sends = 0;
    const security = { ...direct, ...changed };
    const integration = createTeeProvider({ id: "test", name: "Test", baseUrl: model.baseUrl, apiKeyEnv: "TEST_KEY", policy: "public-builds,egress=metadata",
      parseCatalog: () => [model], catalogFetch: async () => Response.json({}), assumptions: [], openSdkTransport: async () => { sends++; throw Error(); },
      routes: [{ id: direct.route, potential: direct, openSession: async () => { throw new RouteRejection(security); } }],
    });
    await integration.initializeCatalog();
    const result = await integration.provider.streamSimple(model, normalizeContext({ messages: [{ role: "user", content: "synthetic", timestamp: 1 }] }), { apiKey: "synthetic-key" }).result();
    assert.equal(result.errorMessage, "TEE_POLICY_ROUTE_REJECTED"); assert.equal(sends, 0);
    const decision = integration.getReport().routeDecisions![0]!;
    assert.deepEqual(decision.security, security); assert.equal(decision.accepted, false);
    assert.match(decision.reason, new RegExp(Object.keys(changed)[0]!));
  }
});
