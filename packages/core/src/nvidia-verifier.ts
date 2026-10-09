import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Worker } from "node:worker_threads";
import { gunzipSync } from "node:zlib";
import { NVIDIA_ARTIFACTS } from "./nvidia-artifacts.js";
import { TeeError } from "./policy.js";
import { compileVerifiedWasm } from "./wasi.js";

// NVIDIA's verifier ships inside this package as WebAssembly and runs in a
// worker thread. It reaches only NVIDIA's reference and revocation services
// through the bounded request bridge. Pins cover the uncompressed module bytes
// and the JavaScript glue.
const location = (name: string) => new URL(`../wasm/${name}`, import.meta.url);
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

async function read(name: string): Promise<Buffer> {
  try { return await readFile(location(name)); } catch { throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED"); }
}
// The worker imports the glue from these authenticated bytes, never from its path.
async function glueArtifact() {
  const bytes = await read("nvattest.mjs");
  if (sha256(bytes) !== NVIDIA_ARTIFACTS["nvattest.mjs"]) throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED");
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}
let module: Promise<WebAssembly.Module> | undefined;
function compiled() {
  if (!module) {
    module = read("nvattest.wasm.gz").then(bytes => {
      let wasm: Uint8Array<ArrayBuffer>;
      try { wasm = new Uint8Array(gunzipSync(bytes, { maxOutputLength: 128 * 1024 * 1024 })); } catch { throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED"); }
      return compileVerifiedWasm(wasm, NVIDIA_ARTIFACTS["nvattest.wasm"]);
    });
    module.catch(() => { module = undefined; });
  }
  return module;
}

export const NVIDIA_VERIFIER_DIGEST = createHash("sha256").update(JSON.stringify([NVIDIA_ARTIFACTS["nvattest.wasm"], NVIDIA_ARTIFACTS["nvattest.mjs"]])).digest("hex");

/** Appraises file evidence with NVIDIA's local verifier and returns its JSON result. */
export async function runNvidiaVerifier(options: { evidence: unknown[]; nonce: string; signal: AbortSignal; collateralOrigin?: string }): Promise<{ code: number; stdout: string }> {
  options.signal.throwIfAborted();
  // Tests may relay NVIDIA collateral through a loopback proxy; nothing else can redirect it.
  const origin = options.collateralOrigin;
  if (origin !== undefined && !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(origin)) throw new TeeError("TEE_REQUEST_REJECTED");
  const glue = await glueArtifact();
  const wasm = await compiled();
  // The abort listener below cannot observe an abort during the awaits above.
  options.signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    // Source checkouts run through a TypeScript loader that workers inherit.
    const worker = new Worker(new URL(`./nvattest-worker.${import.meta.url.endsWith(".ts") ? "ts" : "js"}`, import.meta.url), {
      workerData: {
        module: wasm, glue, glueUrl: location("nvattest.mjs").href, evidence: JSON.stringify(options.evidence), collateralOrigin: origin,
        args: ["--log-level", "off", "--format", "json", "attest", "--device", "gpu", "--gpu-evidence-source", "file",
          "--gpu-evidence-file", "/evidence.json", "--verifier", "local", "--nonce", options.nonce,
          ...(origin ? ["--rim-url", origin, "--ocsp-url", `${origin}/ocsp`] : [])],
      },
      // With NODE_USE_ENV_PROXY or --use-env-proxy, Node workers take HTTP(S)_PROXY
      // from their own environment; an empty one keeps the bridge direct. Bun
      // ignores this option and applies HTTP(S)_PROXY to fetch.
      env: {},
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
