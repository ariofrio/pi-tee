import { parentPort, workerData } from "node:worker_threads";
import { runWasiSync } from "./wasi.js";

try {
  const { module, args, env, stdin, maxStdout } = workerData as { module: WebAssembly.Module; args: string[]; env?: Record<string, string>; stdin?: Uint8Array; maxStdout: number };
  const result = runWasiSync(module, { args, env, stdin, maxStdout });
  parentPort!.postMessage(result, [result.stdout.buffer as ArrayBuffer]);
} catch {
  parentPort!.postMessage({ error: true });
}
