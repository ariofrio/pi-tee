import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { compileVerifiedWasm, runWasiCommand } from "pi-tee-core";
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
