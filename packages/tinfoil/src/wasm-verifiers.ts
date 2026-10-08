import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Worker } from "node:worker_threads";
import { gunzipSync } from "node:zlib";
import { compileVerifiedWasm, runWasiCommand, TeeError } from "pi-tee-core";
import { WASM_ARTIFACTS } from "./wasm-artifacts.js";

// The verifiers ship inside this package as WebAssembly. They run in worker
// threads: the CPU helper has no filesystem or network access; the NVIDIA
// verifier reaches only NVIDIA's reference and revocation services through
// the bounded request bridge below.
// Pins cover the uncompressed module bytes and the JavaScript glue.
const location = (name: string) => new URL(`../wasm/${name}`, import.meta.url);
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

async function read(name: string): Promise<Buffer> {
  try { return await readFile(location(name)); } catch { throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED"); }
}
// The worker imports the glue from these authenticated bytes, never from its path.
async function glueArtifact() {
  const bytes = await read("nvattest.mjs");
  if (sha256(bytes) !== WASM_ARTIFACTS["nvattest.mjs"]) throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED");
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}
const modules = new Map<string, Promise<WebAssembly.Module>>();
function compiled(name: "tinfoil-public-build.wasm" | "nvattest.wasm") {
  let module = modules.get(name);
  if (!module) {
    module = read(`${name}.gz`).then(bytes => {
      let wasm: Uint8Array<ArrayBuffer>;
      try { wasm = new Uint8Array(gunzipSync(bytes, { maxOutputLength: 128 * 1024 * 1024 })); } catch { throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED"); }
      return compileVerifiedWasm(wasm, WASM_ARTIFACTS[name]);
    });
    module.catch(() => modules.delete(name));
    modules.set(name, module);
  }
  return module;
}

export const PUBLIC_BUILD_HELPER_DIGEST = WASM_ARTIFACTS["tinfoil-public-build.wasm"];
export const NVIDIA_VERIFIER_DIGEST = createHash("sha256").update(JSON.stringify([WASM_ARTIFACTS["nvattest.wasm"], WASM_ARTIFACTS["nvattest.mjs"]])).digest("hex");

/** Runs one public-build helper command; the JSON protocol is unchanged from the native helper. */
export async function runPublicBuildHelper(input: string, args: string[], signal: AbortSignal): Promise<{ code: number; stdout: string }> {
  const module = await compiled("tinfoil-public-build.wasm");
  const result = await runWasiCommand(module, {
    args: ["tinfoil-public-build-verifier", ...args], env: { TZ: "UTC" }, stdin: new TextEncoder().encode(input),
    maxStdout: 16384, signal, timeoutMs: 60000,
  });
  return { code: result.code, stdout: new TextDecoder("utf-8", { fatal: true }).decode(result.stdout) };
}

/** Appraises file evidence with NVIDIA's local verifier and returns its JSON result. */
export async function runNvidiaVerifier(options: { evidence: unknown[]; nonce: string; signal: AbortSignal; collateralOrigin?: string }): Promise<{ code: number; stdout: string }> {
  options.signal.throwIfAborted();
  // Tests may relay NVIDIA collateral through a loopback proxy; nothing else can redirect it.
  const origin = options.collateralOrigin;
  if (origin !== undefined && !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(origin)) throw new TeeError("TEE_REQUEST_REJECTED");
  const glue = await glueArtifact();
  const module = await compiled("nvattest.wasm");
  // The abort listener below cannot observe an abort during the awaits above.
  options.signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    // Source checkouts run through a TypeScript loader that workers inherit.
    const worker = new Worker(new URL(`./nvattest-worker.${import.meta.url.endsWith(".ts") ? "ts" : "js"}`, import.meta.url), {
      workerData: {
        module, glue, glueUrl: location("nvattest.mjs").href, evidence: JSON.stringify(options.evidence), collateralOrigin: origin,
        args: ["--log-level", "off", "--format", "json", "attest", "--device", "gpu", "--gpu-evidence-source", "file",
          "--gpu-evidence-file", "/evidence.json", "--verifier", "local", "--nonce", options.nonce,
          ...(origin ? ["--rim-url", origin, "--ocsp-url", `${origin}/ocsp`] : [])],
      },
      resourceLimits: { maxOldGenerationSizeMb: 256 },
    });
    let settled = false;
    const finish = (error?: unknown, value?: { code: number; stdout: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal.removeEventListener("abort", abort);
      void worker.terminate();
      if (error) reject(error); else resolve(value!);
    };
    const abort = () => finish(options.signal.reason ?? new TeeError("TEE_VERIFIER_PROCESS_REJECTED"));
    const timer = setTimeout(() => finish(new TeeError("TEE_VERIFIER_PROCESS_REJECTED")), 120000);
    options.signal.addEventListener("abort", abort, { once: true });
    worker.once("message", (message: { code: number; stdout: string } | { error: true }) => {
      if ("error" in message) finish(new TeeError("TEE_VERIFIER_PROCESS_REJECTED"));
      else finish(undefined, message);
    });
    worker.once("error", () => finish(new TeeError("TEE_VERIFIER_PROCESS_REJECTED")));
    worker.once("exit", () => finish(new TeeError("TEE_VERIFIER_PROCESS_REJECTED")));
  });
}
