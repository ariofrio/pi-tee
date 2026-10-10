import assert from "node:assert/strict";
import { test } from "node:test";
import { RouteRejection, TeeError, parsePolicy } from "pi-tee-core";
import { reuseAfterCompleteResponse, selectPublicWorker } from "../packages/tinfoil/src/public-session.js";

const keys = (host: string, level: 1 | 2 = 1) => ({ tls: "a".repeat(64), hpke: "b".repeat(64), publicBuild: { host, checkedAt: Date.now(), expiresAt: Date.now() + 60000 },
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
  assert.equal(appraised.length, 8);
  await assert.rejects(selectPublicWorker("gemma4-31b", AbortSignal.timeout(5000), {
    discover: async () => ["h0"], reachable: async () => [], appraise: async (_model, host) => keys(host),
  }), /TEE_PUBLIC_BUILD_DEPLOYMENT_UNAVAILABLE/);
});

test("selection reaches a qualifying worker after four rejected candidates", async () => {
  let attempted = 0;
  const selected = await selectPublicWorker("gemma4-31b", AbortSignal.timeout(5000), {
    discover: async () => Array.from({ length: 8 }, (_, i) => `h${i}`), reachable: async hosts => hosts,
    appraise: async (_model, host) => { if (++attempted <= 4) throw new TeeError("TEE_CPU_POLICY_REJECTED"); return keys(host); },
  });
  assert.ok(selected.keys.security.cpuVerified);
  assert.equal(attempted, 5);
});

test("gpu=unchecked stops at the strongest achievable current worker", async () => {
  let attempts = 0;
  await selectPublicWorker("gemma4-31b", AbortSignal.timeout(5000), {
    discover: async () => ["unchecked-a", "unchecked-b"], reachable: async hosts => hosts,
    appraise: async (_model, host) => { attempts++; return { ...keys(host), security: { ...keys(host).security, gpu: 3 } }; },
  }, parsePolicy("public-builds-trust-host,egress=metadata,host=current,gpu=unchecked"));
  assert.equal(attempts, 1);
});


test("selection retains the strongest authenticated rejected worker, rather than an unrated failure", async () => {
  await assert.rejects(selectPublicWorker("gemma4-31b", AbortSignal.timeout(5000), {
    discover: async () => ["genoa", "current-gpu-gap", "unavailable"], reachable: async hosts => hosts,
    appraise: async (_model, host) => {
      if (host === "unavailable") throw new TeeError("TEE_ATTESTATION_REJECTED");
      const result = keys(host, host === "genoa" ? 2 : 1);
      if (host === "current-gpu-gap") result.security.gpu = 2;
      return result;
    },
  }, parsePolicy()), error => {
    assert.ok(error instanceof RouteRejection); assert.equal(error.security.host, 1); assert.equal(error.security.gpu, 2);
    assert.deepEqual(error.security.observed, ["current-gpu-gap"]); return true;
  });
});

test("appraisal=reuse serves later requests from an appraisal whose dispatch completed, under the same policy and route only", async () => {
  let expiresAt = Date.now() + 60000;
  const appraised: string[] = [];
  const deps = { discover: async () => ["w"], reachable: async (hosts: string[]) => hosts,
    appraise: async (_model: unknown, host: string) => { appraised.push(host); const result = keys(host); result.publicBuild.checkedAt = Date.now(); result.publicBuild.expiresAt = expiresAt; return result; } };
  const select = (policy: string, scope = "direct") => selectPublicWorker("gemma4-31b", AbortSignal.timeout(5000), deps, parsePolicy(policy), scope);
  const reuse = "public-builds,egress=metadata,appraisal=reuse";

  (await select("public-builds,egress=metadata")).settle(true);
  await select("public-builds,egress=metadata");
  assert.equal(appraised.length, 2, "per-request appraisal is the default");

  const first = await select(reuse);
  await select(reuse);
  assert.equal(appraised.length, 4, "an unfinished dispatch's appraisal is not reusable");
  first.settle(true);
  const second = await select(reuse);
  assert.equal(appraised.length, 4);
  assert.equal(second.host, first.host);
  assert.deepEqual(first.keys.security.observed, ["w"]);
  assert.match(second.keys.security.observed.at(-1)!, /^Reused the appraisal checked at .*no fresh challenge/);
  assert.notEqual(second.keys, first.keys, "reported observations never alter the stored appraisal");
  await select(reuse);
  assert.equal(appraised.length, 5, "a reused appraisal is unavailable while its dispatch is unfinished");

  await select(`${reuse},verifier=nras`);
  await select(reuse, "gateway");
  assert.equal(appraised.length, 7, "another policy or route appraises afresh");

  second.settle(false);
  second.settle(true);
  await select(reuse);
  assert.equal(appraised.length, 8, "a failed dispatch drops the appraisal, and a lease settles once");

  expiresAt = Date.now() + 4000;
  (await select(reuse, "short")).settle(true);
  await select(reuse, "short");
  assert.equal(appraised.length, 10, "an appraisal close to its admission expiry is not reused");
});

const lease = () => { const settled: boolean[] = []; return { settled, settle: (complete: boolean) => { settled.push(complete); } }; };
const wrap = (fetch: typeof globalThis.fetch, settle: (complete: boolean) => void, signal = new AbortController().signal, dispose?: () => void) =>
  reuseAfterCompleteResponse(signal, { baseUrl: "https://w/v1", fetch, dispose }, settle);

test("only a response read to its end authorizes reuse; rejected or failed dispatches do not", async () => {
  const done = lease(), rejected = lease(), failed = lease();
  assert.equal(await (await wrap(async () => new Response("ok"), done.settle).fetch("https://w/v1/chat/completions")).text(), "ok");
  assert.deepEqual(done.settled, [true]);
  await wrap(async () => new Response("", { status: 412 }), rejected.settle).fetch("https://w/v1/chat/completions");
  await assert.rejects(wrap(async () => { throw new TeeError("TEE_RESPONSE_REJECTED"); }, failed.settle).fetch("https://w/v1/chat/completions"), /TEE_RESPONSE_REJECTED/);
  assert.deepEqual([rejected.settled, failed.settled], [[false], [false]]);
});

test("an errored, cancelled, aborted or disposed response never authorizes reuse; an unfinished one stays unsettled", async () => {
  const chunk = new TextEncoder().encode("chunk");
  const open = (end: "close" | "error" | "open", settle: (complete: boolean) => void, signal?: AbortSignal, dispose?: () => void) =>
    wrap(async () => new Response(new ReadableStream<Uint8Array>({ start(controller) {
      for (let index = 0; index < 8; index++) controller.enqueue(chunk);
      if (end === "close") controller.close(); else if (end === "error") controller.error(new TeeError("TEE_RESPONSE_REJECTED"));
    } })), settle, signal, dispose).fetch("https://w/v1/chat/completions");
  const pause = () => new Promise(resolve => setTimeout(resolve, 20));

  const errored = lease();
  await assert.rejects((await open("error", errored.settle)).text(), /TEE_RESPONSE_REJECTED/);
  const cancelled = lease();
  await (await open("close", cancelled.settle)).body!.cancel();
  assert.deepEqual([errored.settled, cancelled.settled], [[false], [false]]);

  const unfinished = lease();
  const partial = (await open("open", unfinished.settle)).body!.getReader();
  await partial.read();
  await pause();
  assert.deepEqual(unfinished.settled, [], "no end yet");

  const aborted = lease(), abort = new AbortController();
  const backpressured = (await open("open", aborted.settle, abort.signal)).body!.getReader();
  await backpressured.read();
  await pause();
  abort.abort();
  assert.deepEqual(aborted.settled, [false], "abort drops the appraisal without a pending read");

  const disposed = lease();
  let inner = 0;
  const transport = wrap(async () => new Response(new ReadableStream({ start(controller) { controller.enqueue(chunk); } })), disposed.settle, undefined, () => { inner++; });
  await transport.fetch("https://w/v1/chat/completions");
  transport.dispose!();
  assert.deepEqual([disposed.settled, inner], [[false], 1], "disposal drops the appraisal and disposes the inner transport");

  const late = lease(), lateAbort = new AbortController();
  assert.equal(await (await open("close", late.settle, lateAbort.signal)).text(), "chunk".repeat(8));
  lateAbort.abort();
  assert.deepEqual(late.settled, [true], "a lease settles once");
});
