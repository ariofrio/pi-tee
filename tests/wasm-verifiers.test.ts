import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { compileVerifiedWasm, runWasiCommand } from "pi-tee-core";
import { runNvidiaVerifier, runPublicBuildHelper } from "../packages/tinfoil/src/wasm-verifiers.js";

// Minimal hand-assembled WASI commands exercising the shim boundary.
const name = (text: string) => [text.length, ...Buffer.from(text)];
const section = (id: number, body: number[]) => [id, body.length, ...body];
function command(code: number[]) {
  return new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
    ...section(1, [3, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 1, 0x7f, 0, 0x60, 0, 0]),
    ...section(2, [2, ...name("wasi_snapshot_preview1"), ...name("fd_prestat_get"), 0, 0, ...name("wasi_snapshot_preview1"), ...name("proc_exit"), 0, 1]),
    ...section(3, [1, 2]),
    ...section(5, [1, 0, 1]),
    ...section(7, [2, ...name("memory"), 2, 0, ...name("_start"), 0, 2]),
    ...section(10, [1, code.length + 1, 0, ...code]),
  ]);
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
