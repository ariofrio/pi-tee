import { parentPort, workerData } from "node:worker_threads";
import { createHash } from "node:crypto";
import { TeeError, readBoundedBody, MAX_REQUEST_BYTES } from "pi-tee-core";
import { loadPrivatemodeSdk } from "./sdk.js";
import { coordinatorFloorObservation } from "./evidence.js";
const port = parentPort!;
for (const method of ["log", "debug", "info", "warn", "error"] as const)
  console[method] = () => undefined;
let sequence = 0;
const pending = new Map<
  number,
  { resolve(value: any): void; reject(error: Error): void }
>();
const rpc = (kind: string, data: object = {}) =>
  new Promise<any>((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, { resolve, reject });
    port.postMessage({ kind, id, ...data });
  });
let attestation: Record<string, unknown> | undefined;
const editions: unknown[] = [];
let nonce: string | undefined;
let initialized = false;
const manifest = Buffer.from(workerData.manifest as Uint8Array);
let attestRequests = 0,
  secretRequests = 0,
  sends = 0;
// This realm belongs to one request. The SDK has no access to the caller's
// global fetch and cannot re-fetch a manifest, redirect or retry inference.
globalThis.fetch = async (input, init) => {
  const request = new Request(input, init);
  const body = request.body
    ? await readBoundedBody(request.body, MAX_REQUEST_BYTES, request.signal)
    : undefined;
  const path = new URL(request.url).pathname;
  if (path === "/privatemode/v1/attest") {
    if (++attestRequests !== 1) throw new TeeError("TEE_ATTESTATION_REJECTED");
    const challenge = JSON.parse(Buffer.from(body!).toString());
    nonce = challenge.Nonce ?? challenge.nonce;
    if (typeof nonce !== "string" || Buffer.from(nonce, "base64").length !== 32)
      throw new TeeError("TEE_ATTESTATION_REJECTED");
  }
  if (path === "/privatemode/v1/secret" && ++secretRequests !== 1)
    throw new TeeError("TEE_ATTESTATION_REJECTED");
  if (path === "/v1/chat/completions" && (!initialized || ++sends !== 1))
    throw new TeeError("TEE_REQUEST_REJECTED");
  const reply = await rpc("network", {
    url: request.url,
    method: request.method,
    headers: [...request.headers],
    body,
    inferenceAllowed: initialized,
  });
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      const read = await rpc("network-read", { stream: reply.stream });
      if (read.done) controller.close();
      else controller.enqueue(read.value);
    },
    async cancel() {
      await rpc("network-cancel", { stream: reply.stream });
    },
  });
  const response = new Response(stream, {
    status: reply.status,
    headers: reply.headers,
  });
  if (path === "/privatemode/v1/attest" && response.ok) {
    const data = (await response.clone().json()) as { AttestationDoc: string };
    const doc = JSON.parse(
      Buffer.from(data.AttestationDoc, "base64").toString(),
    ) as Record<string, unknown>;
    const manifests = doc.manifests as string[];
    if (
      !Array.isArray(manifests) ||
      manifests.length !== 1 ||
      !Buffer.from(manifests[0]!, "base64").equals(manifest)
    )
      throw new TeeError("TEE_WORKLOAD_PIN_REJECTED");
    const oid = (doc.attestation_type as number[]).join(".");
    if (!["1.3.9901.2.1", "1.3.9901.2.2"].includes(oid))
      throw new TeeError("TEE_CPU_POLICY_REJECTED");
    const policies = doc.policies as string[];
    const allowed = Object.keys(JSON.parse(manifest.toString()).Policies);
    if (!Array.isArray(policies))
      throw new TeeError("TEE_WORKLOAD_PIN_REJECTED");
    const hashes = policies.map((policy) =>
      createHash("sha256").update(Buffer.from(policy, "base64")).digest("hex"),
    );
    if (
      hashes.length !== allowed.length ||
      new Set(hashes).size !== allowed.length ||
      allowed.some((hash) => !hashes.includes(hash))
    )
      throw new TeeError("TEE_WORKLOAD_PIN_REJECTED");
    attestation = doc;
  } else if (/\/(tcb|qe\/identity)/.test(path) && response.ok) {
    const collateral = (await response
      .clone()
      .json()
      .catch(() => ({}))) as Record<string, any>;
    editions.push(
      collateral.tcbInfo?.tcbEvaluationDataNumber ??
        collateral.enclaveIdentity?.tcbEvaluationDataNumber,
    );
  }
  return response;
};
let client: Awaited<ReturnType<typeof loadPrivatemodeSdk>>;
port.on("message", (message: any) => {
  if (message.kind === "rpc") {
    const request = pending.get(message.id);
    pending.delete(message.id);
    if (message.error)
      request?.reject(new TeeError("TEE_ATTESTATION_REJECTED"));
    else request?.resolve(message.value);
  } else if (message.kind === "chat") {
    void client
      .streamChatCompletions(message.body, async (chunk) => {
        await rpc("chunk", { chunk });
      })
      .then(
        () => port.postMessage({ kind: "done" }),
        () => port.postMessage({ kind: "error" }),
      );
  }
});
void (async () => {
  try {
    client = await loadPrivatemodeSdk();
    await client.initialize(
      manifest.toString("base64"),
      "apiKey",
      workerData.apiKey,
      "https://api.privatemode.ai",
      false,
    );
    await client.updateSecret();
    if (!attestation || !nonce) throw new TeeError("TEE_ATTESTATION_REJECTED");
    initialized = true;
    port.postMessage({
      kind: "ready",
      observed: [coordinatorFloorObservation(attestation, editions)],
      checkedAt: Date.now(),
    });
  } catch {
    port.postMessage({ kind: "error" });
  }
})();
