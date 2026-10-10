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

function accepted(stdout: string) {
  try { return JSON.parse(stdout).result_code === 0; } catch { return false; }
}

// Reference manifests are signed and named by firmware version. The verifier
// checks each copy's signature, and its signing chain's revocation, on every
// use; only downloads from runs NVIDIA accepted are reused, for an hour.
// Test relays never share them.
const RIM_TTL_MS = 3600000;
const RIM_CACHE_BYTES = 8 * 1024 * 1024;
const rims = new Map<string, { body: Uint8Array; at: number }>();
function cachedRims() {
  const now = Date.now();
  for (const [key, value] of rims) if (now - value.at >= RIM_TTL_MS) rims.delete(key);
  return Object.fromEntries([...rims].map(([key, value]) => [key, value.body]));
}
function keepRims(fetched: Map<string, Uint8Array>) {
  let size = [...rims.values()].reduce((total, value) => total + value.body.length, 0);
  for (const [key, body] of fetched) {
    if (rims.has(key) || size + body.length > RIM_CACHE_BYTES) continue;
    rims.set(key, { body, at: Date.now() });
    size += body.length;
  }
}

type Verdict = { code: number; stdout: string };

// NVIDIA's verifier appraises each GPU independently, so each GPU gets its own
// fresh verifier and their waits on NVIDIA's services overlap. Each verifier
// adds roughly 30-60 MB of WebAssembly and heap. Eight, the most GPUs any
// admitted CVM has, finish in one round; more appraisals queue rather than
// multiply memory.
const MAX_VERIFIERS = 8;
const slots = { running: 0, waiting: [] as (() => void)[] };
/** Waits for a verifier slot; the returned function releases it once. */
export function verifierSlot(signal: AbortSignal, limit = MAX_VERIFIERS, state = slots): Promise<() => void> {
  return new Promise((resolve, reject) => {
    const grant = () => {
      signal.removeEventListener("abort", abort);
      state.running++;
      let released = false;
      resolve(() => { if (released) return; released = true; state.running--; state.waiting.shift()?.(); });
    };
    const abort = () => {
      const index = state.waiting.indexOf(grant);
      if (index >= 0) state.waiting.splice(index, 1);
      reject(signal.reason);
    };
    if (signal.aborted) return reject(signal.reason);
    if (state.running < limit) return grant();
    state.waiting.push(grant);
    signal.addEventListener("abort", abort, { once: true });
  });
}

/** Combines single-GPU verdicts in evidence order; any failure is the whole verdict. */
export function combineGpuVerdicts(verdicts: Verdict[]): Verdict {
  const claims: unknown[] = [];
  for (const verdict of verdicts) {
    let parsed: any;
    try { parsed = JSON.parse(verdict.stdout); } catch { return { code: verdict.code || 1, stdout: verdict.stdout }; }
    if (verdict.code !== 0 || parsed?.result_code !== 0 || !Array.isArray(parsed.claims) || parsed.claims.length !== 1) return { code: verdict.code || 1, stdout: verdict.stdout };
    claims.push(parsed.claims[0]);
  }
  return { code: 0, stdout: JSON.stringify({ result_code: 0, claims }) };
}

/** Appraises file evidence with NVIDIA's local verifier and returns its JSON result. */
export async function runNvidiaVerifier(options: { evidence: unknown[]; nonce: string; signal: AbortSignal; collateralOrigin?: string }): Promise<Verdict> {
  if (options.evidence.length < 2) return runOne(options);
  const controller = new AbortController();
  const signal = AbortSignal.any([options.signal, controller.signal]);
  return combineGpuVerdicts(await Promise.all(options.evidence.map(item =>
    runOne({ ...options, evidence: [item], signal }).catch(error => { controller.abort(error); throw error; }))));
}

async function runOne(options: { evidence: unknown[]; nonce: string; signal: AbortSignal; collateralOrigin?: string }): Promise<Verdict> {
  const release = await verifierSlot(options.signal);
  try { return await runWorker(options); } finally { release(); }
}

async function runWorker(options: { evidence: unknown[]; nonce: string; signal: AbortSignal; collateralOrigin?: string }): Promise<Verdict> {
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
        module: wasm, glue, glueUrl: location("nvattest.mjs").href, evidence: JSON.stringify(options.evidence), collateralOrigin: origin, rims: origin ? {} : cachedRims(),
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
    const fetched = new Map<string, Uint8Array>();
    worker.on("message", (message: { code: number; stdout: string } | { error: true } | { rim: string; body: Uint8Array }) => {
      if ("rim" in message) { if (!origin) fetched.set(message.rim, message.body); }
      else if ("error" in message) finish(new TeeError("TEE_VERIFIER_PROCESS_REJECTED"));
      else {
        if (message.code === 0 && accepted(message.stdout)) keepRims(fetched);
        finish(undefined, message);
      }
    });
    worker.once("error", () => finish(new TeeError("TEE_VERIFIER_PROCESS_REJECTED")));
    worker.once("exit", () => finish(new TeeError("TEE_VERIFIER_PROCESS_REJECTED")));
  });
}
