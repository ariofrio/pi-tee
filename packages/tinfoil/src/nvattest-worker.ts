import { parentPort, workerData } from "node:worker_threads";
import { pathToFileURL } from "node:url";

// NVIDIA's verifier fetches signed reference manifests and OCSP responses. The
// bridge admits only those two public services, bounded and without redirects,
// proxies or credentials; the signatures, not delivery, authenticate the bytes.
const RIM = "https://rim.attestation.nvidia.com";
const OCSP = "https://ocsp.ndis.nvidia.com";
const FORWARDED_HEADERS = new Set(["accept", "content-type", "x-request-id"]);
const { module, glue, evidence, args, collateralOrigin } = workerData as {
  module: WebAssembly.Module; glue: string; evidence: string; args: string[]; collateralOrigin?: string;
};

async function bounded(response: Response, limit: number) {
  const reader = response.body!.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const next = await reader.read();
    if (next.done) break;
    size += next.value.length;
    if (size > limit) { await reader.cancel(); throw Error("response too large"); }
    chunks.push(next.value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}

let requests = 0;
async function request(method: string, url: string, headers: Record<string, unknown>, body: Uint8Array<ArrayBuffer>) {
  if (++requests > 192) throw Error("too many requests");
  const target = new URL(url);
  const origin = (service: string) => target.origin === service || (collateralOrigin !== undefined && target.origin === collateralOrigin);
  const rim = method === "GET" && origin(RIM) && /^\/v1\/rim\/[A-Za-z0-9._-]{1,160}$/.test(target.pathname);
  const ocsp = method === "POST" && origin(OCSP) && (target.pathname === "/" || target.pathname === "/ocsp");
  if ((!rim && !ocsp) || target.search || target.hash || target.username || target.password) throw Error("destination rejected");
  const forwarded = Object.fromEntries(Object.entries(headers).filter(([name, value]) => FORWARDED_HEADERS.has(name.toLowerCase()) && typeof value === "string")) as Record<string, string>;
  const response = await fetch(target, { method, headers: forwarded, body: rim ? undefined : body, redirect: "error", signal: AbortSignal.timeout(15000) });
  if (!response.body) throw Error("missing body");
  return { status: response.status, body: await bounded(response, rim ? 4 * 1024 * 1024 : 65536) };
}

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
    piTeeRequest: request,
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
