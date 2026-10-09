import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { TeeError } from "pi-tee-core";

export interface PrivatemodeWasmClient {
  initialize(
    manifest: string,
    authType: string,
    authValue: string,
    apiBaseURL: string,
    enableLogging: boolean,
  ): Promise<void>;
  updateSecret(): Promise<void>;
  streamChatCompletions(
    body: string,
    onChunk: (chunk: string) => Promise<void>,
    signal?: AbortSignal,
    onHeaders?: (headers: Headers) => void,
  ): Promise<void>;
  close(): void;
}
export const SDK_ARTIFACTS = {
  "wasm.js": "b8559f3f4bd392f7f5527b674f990ed4e7e094f504cc8a86bb8c88f861964224",
  "wasm_exec.js":
    "0c949f4996f9a89698e4b5c586de32249c3b69b7baadb64d220073cc04acba14",
  "errors.js":
    "108f9416b210e6b8ab66a5a8cd746d122500d01ecbc204a4634b5cc1e6c5de61",
  "privatemode.wasm":
    "422d6bfbcba466b0c7b91d9e227a2447b79f768ea65c2a5ed7e31e3c6fba126d",
} as const;
export async function loadPrivatemodeSdk(): Promise<PrivatemodeWasmClient> {
  const base = import.meta.resolve("privatemode-ai");
  const artifacts = new Map<string, Buffer>();
  for (const [name, digest] of Object.entries(SDK_ARTIFACTS)) {
    const bytes = await readFile(new URL(name, base));
    if (createHash("sha256").update(bytes).digest("hex") !== digest)
      throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED");
    artifacts.set(name, bytes);
  }
  // Evaluate only authenticated bytes. Bun cannot import large data URLs;
  // this also avoids a second filesystem read of the JavaScript glue.
  const script = artifacts.get("wasm_exec.js")!.toString();
  new Function(script)();
  const bridge = artifacts
    .get("wasm.js")!
    .toString()
    .replace(/^import .*;\n/gm, "")
    .replace(/^export /gm, "");
  const errors = artifacts
    .get("errors.js")!
    .toString()
    .replace(/^export /gm, "");
  const sdk = new Function(
    `${errors}\n${bridge}\nreturn { initWasm, createWasmClient };`,
  )() as {
    initWasm(bytes: Buffer, hash: string): Promise<void>;
    createWasmClient(): PrivatemodeWasmClient;
  };
  await sdk.initWasm(
    artifacts.get("privatemode.wasm")!,
    SDK_ARTIFACTS["privatemode.wasm"],
  );
  return sdk.createWasmClient();
}
