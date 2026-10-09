import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { openPrivatemodeTransport } from "../packages/privatemode/src/transport.js";
import { shippedManifestPolicy } from "../packages/privatemode/src/manifest.js";
const live =
  process.env.PI_PRIVATEMODE_LIVE === "1" && !!process.env.PRIVATEMODE_API_KEY;

test(
  "live Privatemode authenticates the pin at A2/H3/G3/X3 and rejects nonce, key, replay and closure tampering before content",
  { skip: !live, timeout: 180000 },
  async () => {
    const key = process.env.PRIVATEMODE_API_KEY!;
    const swappedCA = await readFile(
      new URL("./fixtures/privatemode-swapped-ca.pem", import.meta.url),
    );
    let cached: Uint8Array | undefined;
    let inference = 0;
    const base = async (
      input: Parameters<typeof fetch>[0],
      init?: Parameters<typeof fetch>[1],
    ) => {
      const request = new Request(input, init);
      if (new URL(request.url).pathname === "/v1/chat/completions") inference++;
      return fetch(request, { redirect: "error" });
    };
    const open = async (networkFetch: typeof fetch) => {
      const signal = AbortSignal.timeout(30000);
      return openPrivatemodeTransport({
        apiKey: key,
        model: "gpt-oss-120b",
        signal,
        manifest: await shippedManifestPolicy.admit(signal),
        networkFetch,
      });
    };
    const first = await open(async (input, init) => {
      const path = new URL(input instanceof Request ? input.url : String(input))
        .pathname;
      const r = await base(input, init);
      if (path.endsWith("/attest"))
        cached = new Uint8Array(await r.clone().arrayBuffer());
      return r;
    });
    assert.deepEqual(
      [
        first.security.code,
        first.security.host,
        first.security.gpu,
        first.security.egress,
      ],
      [2, 3, 3, 3],
    );
    first.transport.dispose?.();
    assert.ok(cached);
    for (const mutation of [
      "nonce",
      "mesh-key",
      "replay",
      "closure",
      "duplicate-policy",
      "manifest",
      "shadowed-document",
      "secret-signature",
    ] as const) {
      let secretRequests = 0;
      await assert.rejects(
        open(async (input, init) => {
          let request = new Request(input, init);
          const path = new URL(request.url).pathname;
          if (path.endsWith("/secret")) secretRequests++;
          if (path.endsWith("/attest") && mutation === "nonce") {
            const body = (await request.clone().json()) as Record<
              string,
              unknown
            >;
            body.Nonce = Buffer.alloc(32, 5).toString("base64");
            request = new Request(request, { body: JSON.stringify(body) });
          }
          if (path.endsWith("/attest") && mutation === "replay")
            return new Response(Uint8Array.from(cached!), {
              headers: { "content-type": "application/json" },
            });
          const response = await base(request);
          if (
            path.endsWith("/attest") &&
            [
              "mesh-key",
              "closure",
              "duplicate-policy",
              "manifest",
              "shadowed-document",
            ].includes(mutation)
          ) {
            const body = (await response.json()) as {
              AttestationDoc: string;
              attestationdoc?: string;
            };
            const doc = JSON.parse(
              Buffer.from(body.AttestationDoc, "base64").toString(),
            );
            if (mutation === "mesh-key")
              doc.mesh_ca = swappedCA.toString("base64");
            if (mutation === "closure")
              doc.policies.push(
                Buffer.from("outside the admitted closure").toString("base64"),
              );
            if (mutation === "duplicate-policy")
              doc.policies[doc.policies.length - 1] = doc.policies[0] + "\n";
            if (mutation === "manifest")
              doc.manifests[0] = Buffer.concat([
                Buffer.from(doc.manifests[0], "base64"),
                Buffer.from("\n"),
              ]).toString("base64");
            if (mutation === "shadowed-document") {
              body.attestationdoc = body.AttestationDoc;
              doc.raw_attestation_doc = Buffer.from(
                "unauthenticated diagnostic bytes",
              ).toString("base64");
            }
            body.AttestationDoc = Buffer.from(JSON.stringify(doc)).toString(
              "base64",
            );
            return Response.json(body);
          }
          if (path.endsWith("/secret") && mutation === "secret-signature") {
            const body = (await response.json()) as { Signature: string };
            const bytes = Buffer.from(body.Signature, "base64");
            bytes[0] = bytes[0]! ^ 1;
            body.Signature = bytes.toString("base64");
            return Response.json(body);
          }
          return response;
        }),
        /TEE_ATTESTATION_REJECTED/,
        mutation,
      );
      if (mutation !== "secret-signature")
        assert.equal(secretRequests, 0, mutation);
    }
    assert.equal(inference, 0);
  },
);
