import { createHash } from "node:crypto";
import { Worker } from "node:worker_threads";
import { TeeError } from "./policy.js";

// Minimal WASI preview1 for offline verifier modules: argv, a fixed
// environment, clocks, randomness, bounded stdin/stdout and nothing else.
// There are no preopened directories or sockets, so a module cannot read or
// write local files or open connections.
const ERRNO_SUCCESS = 0, ERRNO_BADF = 8, ERRNO_FAULT = 21, ERRNO_INVAL = 28, ERRNO_NOSYS = 52, ERRNO_NOTCAPABLE = 76;
const FILETYPE_CHARACTER_DEVICE = 2;
const EVENTTYPE_CLOCK = 0;

export class WasiExit extends Error {
  constructor(readonly code: number) { super(`exit ${code}`); }
}
class OutputLimit extends Error {}

export interface WasiRunOptions {
  args: string[];
  env?: Record<string, string>;
  stdin?: Uint8Array;
  maxStdout: number;
}

/** Runs a WASI command synchronously in the current thread. Use runWasiCommand for isolation. */
export function runWasiSync(module: WebAssembly.Module, options: WasiRunOptions): { code: number; stdout: Uint8Array } {
  const encoder = new TextEncoder();
  const args = options.args.map(arg => encoder.encode(`${arg}\0`));
  const env = Object.entries(options.env ?? {}).map(([key, value]) => encoder.encode(`${key}=${value}\0`));
  const stdin = options.stdin ?? new Uint8Array();
  let stdinOffset = 0;
  const stdout: Uint8Array[] = [];
  let stdoutBytes = 0;
  let memory: WebAssembly.Memory;
  const view = () => new DataView(memory.buffer);
  const bytes = () => new Uint8Array(memory.buffer);
  const sleeper = new Int32Array(new SharedArrayBuffer(4));
  function strings(list: Uint8Array[], pointers: number, buffer: number) {
    for (const item of list) {
      view().setUint32(pointers, buffer, true); pointers += 4;
      bytes().set(item, buffer); buffer += item.length;
    }
    return ERRNO_SUCCESS;
  }
  function sizes(list: Uint8Array[], count: number, size: number) {
    view().setUint32(count, list.length, true);
    view().setUint32(size, list.reduce((total, item) => total + item.length, 0), true);
    return ERRNO_SUCCESS;
  }
  // Guest pointers and lengths are unsigned; a range past the end of memory is
  // EFAULT, never a shorter read or write.
  const inMemory = (pointer: number, length: number) => (pointer >>> 0) + (length >>> 0) <= memory.buffer.byteLength;
  function iovecs(pointer: number, length: number) {
    const result: [number, number][] = [];
    for (let index = 0; index < length; index++) result.push([view().getUint32(pointer + index * 8, true), view().getUint32(pointer + index * 8 + 4, true)]);
    return result.every(([buffer, size]) => inMemory(buffer, size)) ? result : undefined;
  }
  const stdio = (fd: number) => fd === 0 || fd === 1 || fd === 2;
  const imports: Record<string, (...args: any[]) => number> = {
    args_get: (pointers: number, buffer: number) => strings(args, pointers, buffer),
    args_sizes_get: (count: number, size: number) => sizes(args, count, size),
    environ_get: (pointers: number, buffer: number) => strings(env, pointers, buffer),
    environ_sizes_get: (count: number, size: number) => sizes(env, count, size),
    clock_res_get: (_id: number, result: number) => { view().setBigUint64(result, 1000n, true); return ERRNO_SUCCESS; },
    clock_time_get: (id: number, _precision: bigint, result: number) => {
      const now = id === 0 ? BigInt(Date.now()) * 1_000_000n : BigInt(Math.round(performance.now() * 1_000_000));
      view().setBigUint64(result, now, true);
      return ERRNO_SUCCESS;
    },
    random_get: (pointer: number, length: number) => {
      if (!inMemory(pointer, length)) return ERRNO_FAULT;
      pointer >>>= 0; length >>>= 0;
      for (let offset = 0; offset < length; offset += 65536) crypto.getRandomValues(bytes().subarray(pointer + offset, pointer + Math.min(length, offset + 65536)));
      return ERRNO_SUCCESS;
    },
    fd_write: (fd: number, pointer: number, length: number, written: number) => {
      if (fd !== 1 && fd !== 2) return ERRNO_BADF;
      const buffers = iovecs(pointer, length);
      if (!buffers) return ERRNO_FAULT;
      let total = 0;
      for (const [buffer, size] of buffers) {
        if (fd === 1) {
          stdoutBytes += size;
          if (stdoutBytes > options.maxStdout) throw new OutputLimit();
          stdout.push(bytes().slice(buffer, buffer + size));
        }
        total += size;
      }
      view().setUint32(written, total, true);
      return ERRNO_SUCCESS;
    },
    fd_read: (fd: number, pointer: number, length: number, read: number) => {
      if (fd !== 0) return ERRNO_BADF;
      const buffers = iovecs(pointer, length);
      if (!buffers) return ERRNO_FAULT;
      let total = 0;
      for (const [buffer, size] of buffers) {
        const chunk = stdin.subarray(stdinOffset, stdinOffset + size);
        bytes().set(chunk, buffer); stdinOffset += chunk.length; total += chunk.length;
        if (chunk.length < size) break;
      }
      view().setUint32(read, total, true);
      return ERRNO_SUCCESS;
    },
    fd_fdstat_get: (fd: number, result: number) => {
      if (!stdio(fd)) return ERRNO_BADF;
      bytes().fill(0, result, result + 24);
      view().setUint8(result, FILETYPE_CHARACTER_DEVICE);
      view().setBigUint64(result + 8, 0xffffffffffffffffn, true);
      view().setBigUint64(result + 16, 0xffffffffffffffffn, true);
      return ERRNO_SUCCESS;
    },
    fd_fdstat_set_flags: (fd: number) => stdio(fd) ? ERRNO_SUCCESS : ERRNO_BADF,
    fd_close: (fd: number) => stdio(fd) ? ERRNO_SUCCESS : ERRNO_BADF,
    fd_prestat_get: () => ERRNO_BADF,
    fd_prestat_dir_name: () => ERRNO_BADF,
    poll_oneoff: (input: number, output: number, count: number, events: number) => {
      // Stdio is always ready. Clock subscriptions sleep until the earliest
      // timeout, which only Go's scheduler uses when idle.
      let timeout = Infinity, written = 0;
      for (let index = 0; index < count; index++) {
        const subscription = input + index * 48;
        const type = view().getUint8(subscription + 8);
        const event = output + written * 32;
        bytes().fill(0, event, event + 32);
        view().setBigUint64(event, view().getBigUint64(subscription, true), true);
        view().setUint8(event + 10, type);
        if (type === EVENTTYPE_CLOCK) {
          const absolute = (view().getUint16(subscription + 40, true) & 1) === 1;
          const value = Number(view().getBigUint64(subscription + 24, true)) / 1_000_000;
          timeout = Math.min(timeout, absolute ? value - (view().getUint32(subscription + 16, true) === 0 ? Date.now() : performance.now()) : value);
        } else if (!stdio(view().getUint32(subscription + 16, true))) view().setUint16(event + 8, ERRNO_BADF, true);
        written++;
      }
      if (Number.isFinite(timeout) && timeout > 0) Atomics.wait(sleeper, 0, 0, Math.min(timeout, 1000));
      view().setUint32(events, written, true);
      return ERRNO_SUCCESS;
    },
    sched_yield: () => ERRNO_SUCCESS,
    proc_exit: (code: number) => { throw new WasiExit(code); },
    proc_raise: () => ERRNO_NOSYS,
  };
  const denied = new Proxy(imports, {
    get: (target, name: string) => Object.hasOwn(target, name) ? target[name] : ((..._args: unknown[]) => name.startsWith("path_") ? ERRNO_NOTCAPABLE : name.startsWith("fd_") ? ERRNO_BADF : name.startsWith("sock_") ? ERRNO_NOSYS : ERRNO_INVAL),
  });
  const required = WebAssembly.Module.imports(module);
  if (required.some(item => item.module !== "wasi_snapshot_preview1" || item.kind !== "function")) throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED");
  const instance = new WebAssembly.Instance(module, { wasi_snapshot_preview1: Object.fromEntries(required.map(item => [item.name, denied[item.name]!])) });
  memory = instance.exports.memory as WebAssembly.Memory;
  let code = 0;
  try { (instance.exports._start as () => void)(); } catch (error) {
    if (error instanceof WasiExit) code = error.code;
    else if (error instanceof OutputLimit) code = -1;
    else throw error;
  }
  const result = new Uint8Array(stdoutBytes);
  let offset = 0;
  for (const chunk of stdout) { result.set(chunk, offset); offset += chunk.length; }
  return { code, stdout: result };
}

/** Authenticates module bytes before compilation. */
export function compileVerifiedWasm(bytes: Uint8Array<ArrayBuffer>, sha256: string): WebAssembly.Module {
  if (createHash("sha256").update(bytes).digest("hex") !== sha256) throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED");
  return new WebAssembly.Module(bytes);
}

/**
 * Runs a WASI command in a worker so a long verification cannot block Pi and
 * cancellation or timeout terminates it.
 */
export function runWasiCommand(module: WebAssembly.Module, options: WasiRunOptions & { signal: AbortSignal; timeoutMs: number }): Promise<{ code: number; stdout: Uint8Array }> {
  options.signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL(`./wasi-worker.${import.meta.url.endsWith(".ts") ? "ts" : "js"}`, import.meta.url), {
      workerData: { module, args: options.args, env: options.env, stdin: options.stdin, maxStdout: options.maxStdout },
      resourceLimits: { maxOldGenerationSizeMb: 256 },
    });
    let settled = false;
    const finish = (error?: unknown, value?: { code: number; stdout: Uint8Array }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal.removeEventListener("abort", abort);
      void worker.terminate();
      if (error) reject(error); else resolve(value!);
    };
    const abort = () => finish(options.signal.reason ?? new TeeError("TEE_VERIFIER_PROCESS_REJECTED"));
    const timer = setTimeout(() => finish(new TeeError("TEE_VERIFIER_PROCESS_REJECTED")), options.timeoutMs);
    options.signal.addEventListener("abort", abort, { once: true });
    worker.once("message", (message: { code: number; stdout: Uint8Array } | { error: true }) => {
      if ("error" in message) finish(new TeeError("TEE_VERIFIER_PROCESS_REJECTED"));
      else finish(undefined, { code: message.code, stdout: new Uint8Array(message.stdout) });
    });
    worker.once("error", () => finish(new TeeError("TEE_VERIFIER_PROCESS_REJECTED")));
    worker.once("exit", () => finish(new TeeError("TEE_VERIFIER_PROCESS_REJECTED")));
  });
}
