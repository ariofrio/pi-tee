import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { compileVerifiedWasm, runWasiCommand } from "pi-tee-core";
import { nvidiaCollateralBridge } from "../packages/tinfoil/src/nvattest-bridge.js";
import { runNvidiaVerifier, runPublicBuildHelper } from "../packages/tinfoil/src/wasm-verifiers.js";

// Minimal hand-assembled WASI commands exercising the shim boundary. Imported
// function types: 0 (i32, i32) -> i32, 1 (i32) -> (), 3 (i32, i32, i32, i32) -> i32.
const name = (text: string) => [text.length, ...Buffer.from(text)];
const section = (id: number, body: number[]) => [id, body.length, ...body];
function wasi(imports: [string, number][], code: number[]) {
  return new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
    ...section(1, [4, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 1, 0x7f, 0, 0x60, 0, 0, 0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]),
    ...section(2, [imports.length, ...imports.flatMap(([field, type]) => [...name("wasi_snapshot_preview1"), ...name(field), 0, type])]),
    ...section(3, [1, 2]),
    ...section(5, [1, 0, 1]),
    ...section(7, [2, ...name("memory"), 2, 0, ...name("_start"), 0, imports.length]),
    ...section(10, [1, code.length + 1, 0, ...code]),
  ]);
}
const command = (code: number[]) => wasi([["fd_prestat_get", 0], ["proc_exit", 1]], code);
// i32.const with a signed LEB128 immediate.
function i32(value: number) {
  const bytes = [0x41];
  for (;;) {
    const byte = value & 0x7f;
    value >>= 7;
    if ((value === 0 && !(byte & 0x40)) || (value === -1 && byte & 0x40)) return [...bytes, byte];
    bytes.push(byte | 0x80);
  }
}
const compile = (bytes: Uint8Array<ArrayBuffer>) => compileVerifiedWasm(bytes, createHash("sha256").update(bytes).digest("hex"));
const run = (module: WebAssembly.Module, signal = AbortSignal.timeout(10000), timeoutMs = 10000) =>
  runWasiCommand(module, { args: ["probe"], maxStdout: 1024, signal, timeoutMs });

test("verifier modules are authenticated before compilation", () => {
  const bytes = command([0x41, 0, 0x10, 1, 0x0b]);
  assert.throws(() => compileVerifiedWasm(bytes, "0".repeat(64)), /TEE_VERIFIER_ARTIFACT_REJECTED/);
});

test("the WASI shim exposes no preopened directory", async () => {
  // fd_prestat_get(3) must fail with EBADF (8): a module cannot discover any file system.
  const result = await run(compile(command([0x41, 3, 0x41, 0, 0x10, 0, 0x10, 1, 0x0b])));
  assert.equal(result.code, 8);
});

test("the WASI shim denies imports that are not its own functions", async () => {
  // constructor(0, 0) must reach the deny fallback (EINVAL, 28), not Object.prototype.
  const result = await run(compile(wasi([["constructor", 0], ["proc_exit", 1]], [...i32(0), ...i32(0), 0x10, 0, 0x10, 1, 0x0b])));
  assert.equal(result.code, 28);
});

test("the WASI shim rejects out-of-range buffers instead of truncating them", async () => {
  // random_get across the end of the single 64 KiB page must fail with EFAULT (21).
  const random = await run(compile(wasi([["random_get", 0], ["proc_exit", 1]], [...i32(65528), ...i32(16), 0x10, 0, 0x10, 1, 0x0b])));
  assert.equal(random.code, 21);
  // fd_write(1) of an iovec { 65530, 16 } stored at address 0.
  const write = await run(compile(wasi([["fd_write", 3], ["proc_exit", 1]], [
    ...i32(0), ...i32(65530), 0x36, 2, 0, ...i32(4), ...i32(16), 0x36, 2, 0,
    ...i32(1), ...i32(0), ...i32(1), ...i32(8), 0x10, 0, 0x10, 1, 0x0b])));
  assert.equal(write.code, 21);
  assert.equal(write.stdout.length, 0);
  // fd_read(0) into the same out-of-range iovec.
  const read = await runWasiCommand(compile(wasi([["fd_read", 3], ["proc_exit", 1]], [
    ...i32(0), ...i32(65530), 0x36, 2, 0, ...i32(4), ...i32(16), 0x36, 2, 0,
    ...i32(0), ...i32(0), ...i32(1), ...i32(8), 0x10, 0, 0x10, 1, 0x0b])),
  { args: ["probe"], stdin: new Uint8Array(4), maxStdout: 1024, signal: AbortSignal.timeout(10000), timeoutMs: 10000 });
  assert.equal(read.code, 21);
});

test("cancellation and timeouts terminate a running verifier", async () => {
  const spin = compile(command([0x03, 0x40, 0x0c, 0, 0x0b, 0x0b]));
  const controller = new AbortController();
  setTimeout(() => controller.abort(new Error("cancelled")), 100);
  await assert.rejects(run(spin, controller.signal), /cancelled/);
  await assert.rejects(run(spin, AbortSignal.timeout(10000), 100), /TEE_VERIFIER_PROCESS_REJECTED/);
});

test("the WebAssembly public-build helper authenticates a real guest release offline", async () => {
  const fixture = (file: string) => readFile(`tools/tinfoil-public-build/testdata/${file}`);
  const input = JSON.stringify({ tag: "v0.11.0", manifest: (await fixture("cvm-v0.11.0-manifest.json")).toString("base64"), bundle: JSON.parse((await fixture("cvm-v0.11.0.bundle.json")).toString()) });
  const accepted = await runPublicBuildHelper(input, ["--cvm-build"], AbortSignal.timeout(60000));
  assert.equal(accepted.code, 0);
  const result = JSON.parse(accepted.stdout);
  assert.equal(result.cvmBuildVerified, true);
  assert.equal(result.repo, "tinfoilsh/cvmimage");
  const rejected = await runPublicBuildHelper(input.replace('"v0.11.0"', '"v0.11.1"'), ["--cvm-build"], AbortSignal.timeout(60000));
  assert.notEqual(rejected.code, 0);
});

test("the NVIDIA verifier cannot be redirected to arbitrary collateral services", async () => {
  for (const origin of ["https://rim.attestation.nvidia.com.invalid", "http://localhost:1", "http://127.0.0.1:1/path"]) {
    await assert.rejects(runNvidiaVerifier({ evidence: [], nonce: "0".repeat(64), signal: AbortSignal.timeout(10000), collateralOrigin: origin }), /TEE_REQUEST_REJECTED/);
  }
});

test("the NVIDIA verifier starts offline and rejects empty evidence", async () => {
  const result = await runNvidiaVerifier({ evidence: [], nonce: "0".repeat(64), signal: AbortSignal.timeout(60000) });
  assert.notEqual(result.code, 0);
  assert.notEqual(JSON.parse(result.stdout).result_code, 0);
});

test("the NVIDIA verifier honors cancellation that arrives while it is starting", async () => {
  const controller = new AbortController();
  const pending = runNvidiaVerifier({ evidence: [], nonce: "0".repeat(64), signal: controller.signal });
  controller.abort(new Error("cancelled"));
  await assert.rejects(pending, /cancelled/);
});

// The bridge is the NVIDIA verifier's only network path. A stub fetch observes
// exactly what would leave the worker.
function stubFetch() {
  const calls: { url: string; method?: string; headers: Record<string, string>; body?: unknown; redirect?: string; signal: boolean }[] = [];
  const stub = {
    calls,
    reply: () => new Response(new Uint8Array(8)),
    fetch: (async (input: string | URL, init: RequestInit = {}) => {
      calls.push({ url: String(input), method: init.method, headers: { ...init.headers as Record<string, string> }, body: init.body, redirect: init.redirect, signal: init.signal instanceof AbortSignal });
      return stub.reply();
    }) as typeof fetch,
  };
  return stub;
}

test("the NVIDIA collateral bridge forwards only bounded requests to NVIDIA's two services", async () => {
  const stub = stubFetch();
  const request = nvidiaCollateralBridge({ fetch: stub.fetch });
  const empty = new Uint8Array();
  const headers = { Accept: "application/json", "Content-Type": "application/ocsp-request", "X-Request-Id": "r", Authorization: "Bearer key", "User-Agent": "nvattest", Cookie: "c", Count: 1 };
  assert.deepEqual(await request("GET", "https://rim.attestation.nvidia.com/v1/rim/NV_GPU_DRIVER_GH100_595.71.05", headers, new Uint8Array([1])), { status: 200, body: new Uint8Array(8) });
  assert.deepEqual(stub.calls[0], { url: "https://rim.attestation.nvidia.com/v1/rim/NV_GPU_DRIVER_GH100_595.71.05", method: "GET",
    headers: { Accept: "application/json", "Content-Type": "application/ocsp-request", "X-Request-Id": "r" }, body: undefined, redirect: "error", signal: true });
  const ocsp = new Uint8Array([0x30, 0]);
  await request("POST", "https://ocsp.ndis.nvidia.com", {}, ocsp);
  assert.deepEqual(stub.calls[1], { url: "https://ocsp.ndis.nvidia.com/", method: "POST", headers: {}, body: ocsp, redirect: "error", signal: true });
  // NVIDIA's client handles non-2xx statuses itself.
  stub.reply = () => new Response("missing", { status: 404 });
  assert.equal((await request("GET", "https://rim.attestation.nvidia.com/v1/rim/X", {}, empty)).status, 404);

  const forwarded = stub.calls.length;
  for (const [method, url] of [
    ["GET", "https://rim.attestation.nvidia.com/v1/rim/../../v2/X"], ["GET", "https://rim.attestation.nvidia.com/v1/rim/X?a=1"],
    ["GET", "https://rim.attestation.nvidia.com/v1/rim/X#a"], ["GET", "https://user:pass@rim.attestation.nvidia.com/v1/rim/X"],
    ["GET", "http://rim.attestation.nvidia.com/v1/rim/X"], ["GET", "https://rim.attestation.nvidia.com:8443/v1/rim/X"],
    ["GET", "https://rim.attestation.nvidia.com.example/v1/rim/X"], ["GET", `https://rim.attestation.nvidia.com/v1/rim/${"A".repeat(161)}`],
    ["POST", "https://rim.attestation.nvidia.com/v1/rim/X"], ["GET", "https://ocsp.ndis.nvidia.com/"], ["PUT", "https://ocsp.ndis.nvidia.com/"],
    ["POST", "https://ocsp.ndis.nvidia.com/ocsp/x"], ["POST", "https://nras.attestation.nvidia.com/v4/attest/gpu"], ["GET", "http://127.0.0.1:8080/v1/rim/X"],
  ]) await assert.rejects(request(method!, url!, {}, empty), `${method} ${url}`);
  assert.equal(stub.calls.length, forwarded);

  // Reference manifests are limited to 4 MiB and OCSP responses to 64 KiB.
  stub.reply = () => new Response(new Uint8Array(4 * 1024 * 1024 + 1));
  await assert.rejects(request("GET", "https://rim.attestation.nvidia.com/v1/rim/X", {}, empty));
  stub.reply = () => new Response(new Uint8Array(65537));
  await assert.rejects(request("POST", "https://ocsp.ndis.nvidia.com/", {}, empty));
  stub.reply = () => new Response(new Uint8Array(65536));
  assert.equal((await request("POST", "https://ocsp.ndis.nvidia.com/", {}, empty)).body.length, 65536);
});

test("the NVIDIA collateral bridge admits only its loopback test relay and at most 192 requests", async () => {
  const stub = stubFetch();
  const request = nvidiaCollateralBridge({ fetch: stub.fetch, collateralOrigin: "http://127.0.0.1:8080" });
  const empty = new Uint8Array();
  await request("GET", "http://127.0.0.1:8080/v1/rim/X", {}, empty);
  await request("POST", "http://127.0.0.1:8080/ocsp", {}, empty);
  await assert.rejects(request("GET", "http://127.0.0.1:8081/v1/rim/X", {}, empty));
  for (let count = 3; count < 192; count++) await request("GET", "https://rim.attestation.nvidia.com/v1/rim/X", {}, empty);
  assert.equal(stub.calls.length, 191);
  await assert.rejects(request("GET", "https://rim.attestation.nvidia.com/v1/rim/X", {}, empty));
  assert.equal(stub.calls.length, 191);
});
