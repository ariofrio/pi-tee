import { parentPort, workerData } from "node:worker_threads";
import { pathToFileURL } from "node:url";

const { module, glue, evidence, args, collateralOrigin } = workerData as {
  module: WebAssembly.Module; glue: string; evidence: string; args: string[]; collateralOrigin?: string;
};

// Source checkouts start this worker from TypeScript without the loader's
// .js-to-.ts mapping, so the sibling module is named by this file's extension.
const { nvidiaCollateralBridge }: typeof import("./nvattest-bridge.js") =
  await import(new URL(`./nvattest-bridge.${import.meta.url.endsWith(".ts") ? "ts" : "js"}`, import.meta.url).href);

try {
  let stdout = "", overflow = false;
  const { default: createNvattest } = await import(pathToFileURL(glue).href);
  const runtime = await createNvattest({
    noInitialRun: true,
    instantiateWasm(imports: WebAssembly.Imports, success: (instance: WebAssembly.Instance, module: WebAssembly.Module) => void) {
      const instance = new WebAssembly.Instance(module, imports);
      success(instance, module);
      return instance.exports;
    },
    print(line: string) { if (stdout.length + line.length > 262144) overflow = true; else stdout += `${line}\n`; },
    printErr() {},
    piTeeRequest: nvidiaCollateralBridge({ collateralOrigin }),
  });
  runtime.FS.writeFile("/evidence.json", evidence);
  // An asynchronous ccall returns main's status after network waits; callMain
  // under Asyncify would report the exit status before main resumes.
  const argv = ["nvattest", ...args].map(arg => runtime.stringToNewUTF8(arg) as number);
  const pointer = runtime._malloc(4 * (argv.length + 1)) as number;
  argv.forEach((value, index) => { runtime.HEAPU32[(pointer >> 2) + index] = value; });
  runtime.HEAPU32[(pointer >> 2) + argv.length] = 0;
  let code: number;
  try { code = await runtime.ccall("main", "number", ["number", "number"], [argv.length, pointer], { async: true }); } catch (error: any) {
    if (error?.name !== "ExitStatus") throw error;
    code = error.status;
  }
  parentPort!.postMessage(overflow ? { error: true } : { code, stdout });
} catch {
  parentPort!.postMessage({ error: true });
}
