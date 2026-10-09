import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { openNearGatewayTransport } from "../packages/nearai/src/gateway.js";

test("the gateway route keeps evidence, metadata and inference on its one channel and approves nothing it could not verify", async () => {
  const fixture = JSON.parse(await readFile("tests/fixtures/near-gateway-attestation.json", "utf8"));
  const contacted: string[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    contacted.push(new URL(new Request(input, init).url).host);
    throw new Error("network disabled in this test");
  }) as typeof fetch;
  const requests: string[] = [];
  let approvals = 0, closed = false;
  // Serves the recorded public report under the client's fresh nonce; the quote
  // no longer binds that nonce, so appraisal must fail before any approval.
  const request = async (request: Request) => {
    const url = new URL(request.url);
    requests.push(`${request.method} ${url.pathname} ${request.headers.get("authorization")}`);
    if (url.pathname === "/v1/attestation/report" && !url.searchParams.has("model")) {
      const body = { ...fixture, gateway_attestation: { ...fixture.gateway_attestation, request_nonce: url.searchParams.get("nonce") } };
      return { response: Response.json(body), peerSpkiFingerprint: fixture.gateway_attestation.tls_cert_fingerprint };
    }
    if (url.pathname === "/v1/model/z-ai%2Fglm-5.3-flash") {
      return { response: Response.json({ modelId: "z-ai/glm-5.3-flash", metadata: { verifiable: true } }), peerSpkiFingerprint: fixture.gateway_attestation.tls_cert_fingerprint };
    }
    return { response: new Response("unavailable", { status: 503 }), peerSpkiFingerprint: fixture.gateway_attestation.tls_cert_fingerprint };
  };
  const channel = {
    request,
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => (await request(new Request(input, init))).response) as typeof fetch,
    approve() { approvals++; },
    close() { closed = true; },
  };
  try {
    await assert.rejects(openNearGatewayTransport("synthetic-key", AbortSignal.timeout(30000), "z-ai/glm-5.3-flash", {
      channel, cpu: { collateral: async () => { throw new Error("synthetic CPU failure"); } },
    }));
  } finally { globalThis.fetch = realFetch; }
  assert.deepEqual(contacted, []);
  assert.equal(requests[0], "GET /v1/attestation/report Bearer synthetic-key");
  assert.ok(requests.every(line => line.startsWith("GET ") && line.endsWith(" Bearer synthetic-key")), requests.join("\n"));
  assert.equal(approvals, 0);
  assert.equal(closed, true);
});
