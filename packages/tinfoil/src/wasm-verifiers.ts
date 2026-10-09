import { gunzipSync } from "node:zlib";
import { readFile } from "node:fs/promises";
import { compileVerifiedWasm, runWasiCommand, TeeError } from "pi-tee-core";
import { WASM_ARTIFACTS } from "./wasm-artifacts.js";

// The public-build CPU/release helper ships inside this package as a WASI
// command with no filesystem or network access. NVIDIA's verifier ships in
// pi-tee-core. Pins cover the uncompressed module bytes.
export { NVIDIA_VERIFIER_DIGEST, runNvidiaVerifier } from "pi-tee-core";

let module: Promise<WebAssembly.Module> | undefined;
function compiled() {
  if (!module) {
    module = readFile(new URL("../wasm/tinfoil-public-build.wasm.gz", import.meta.url)).catch(() => { throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED"); }).then(bytes => {
      let wasm: Uint8Array<ArrayBuffer>;
      try { wasm = new Uint8Array(gunzipSync(bytes, { maxOutputLength: 128 * 1024 * 1024 })); } catch { throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED"); }
      return compileVerifiedWasm(wasm, WASM_ARTIFACTS["tinfoil-public-build.wasm"]);
    });
    module.catch(() => { module = undefined; });
  }
  return module;
}

export const PUBLIC_BUILD_HELPER_DIGEST = WASM_ARTIFACTS["tinfoil-public-build.wasm"];

/** Runs one public-build helper command; the JSON protocol is unchanged from the native helper. */
export async function runPublicBuildHelper(input: string, args: string[], signal: AbortSignal): Promise<{ code: number; stdout: string }> {
  const helper = await compiled();
  const result = await runWasiCommand(helper, {
    args: ["tinfoil-public-build-verifier", ...args], env: { TZ: "UTC" }, stdin: new TextEncoder().encode(input),
    maxStdout: 16384, signal, timeoutMs: 60000,
  });
  return { code: result.code, stdout: new TextDecoder("utf-8", { fatal: true }).decode(result.stdout) };
}
