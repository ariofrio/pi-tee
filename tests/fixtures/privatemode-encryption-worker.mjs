import { parentPort, workerData } from "node:worker_threads";
import { loadPrivatemodeSdk } from "../../packages/privatemode/dist/sdk.js";
// Fixture-only known secret: exercise the actual SDK's cryptographic wire
// boundary without claiming that this offline test qualifies a deployment.
globalThis.fetch = async (input, init) => {
  const request = new Request(input, init);
  const bytes = new Uint8Array(await request.arrayBuffer());
  parentPort.postMessage({
    kind: "wire",
    headers: [...request.headers],
    url: request.url,
    bytes,
  });
  return new Response(
    'data: {"choices":[{"delta":{"content":"untrusted plaintext"}}]}\n\n',
    { headers: { "content-type": "text/event-stream" } },
  );
};
try {
  const client = await loadPrivatemodeSdk();
  client.initializeOffline(
    "apiKey",
    "fixture-key",
    "https://api.privatemode.ai",
    false,
  );
  client.importSecret(
    "fixture-secret",
    Buffer.alloc(32, 1).toString("base64"),
    Math.floor(Date.now() / 1000) + 60,
  );
  await client.streamChatCompletions(
    JSON.stringify(workerData.body),
    async (chunk) => parentPort.postMessage({ kind: "chunk", chunk }),
  );
  parentPort.postMessage({ kind: "accepted" });
} catch {
  parentPort.postMessage({ kind: "rejected" });
}
