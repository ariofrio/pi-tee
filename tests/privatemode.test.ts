import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeContext } from "@earendil-works/pi-ai/compat";
import { openAICompletionsApi } from "@earendil-works/pi-ai/compat";
import {
  privatemodeCatalog,
  SHIPPED_CATALOG,
} from "../packages/privatemode/src/catalog.js";
import { createPinnedManifestPolicy } from "../packages/privatemode/src/manifest.js";

test("native Pi reasoning-off selects the supported minimum effort instead of the server's default", async () => {
  for (const model of privatemodeCatalog(SHIPPED_CATALOG)) {
    let effort: unknown;
    await openAICompletionsApi()
      .streamSimple(
        model,
        normalizeContext({
          messages: [{ role: "user", content: "synthetic", timestamp: 1 }],
        }),
        {
          apiKey: "fixture-key",
          reasoning: undefined,
          fetch: async (input, init) => {
            effort = (
              (await new Request(input, init).json()) as Record<string, unknown>
            ).reasoning_effort;
            return new Response(
              'data: {"id":"fixture","choices":[{"index":0,"delta":{"content":"OK"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n',
              { headers: { "content-type": "text/event-stream" } },
            );
          },
        },
      )
      .result();
    assert.equal(effort, "low", model.id);
  }
});

test("manifest admission holds an exact immutable pin and refuses a changed digest", async () => {
  const bytes = new TextEncoder().encode('{"Policies":{}}');
  const policy = createPinnedManifestPolicy(
    bytes,
    "ad420d1653bc336a925f43068d0b50d237b44ccbc16ebfa8a5fc43756d50ed7d",
    "fixture",
  );
  const first = await policy.admit(AbortSignal.timeout(1000));
  assert.deepEqual(first.bytes, bytes);
  bytes[0] = 0;
  first.bytes[0] = 0;
  assert.equal((await policy.admit(AbortSignal.timeout(1000))).bytes[0], 123);
  assert.throws(
    () =>
      createPinnedManifestPolicy(new Uint8Array(1), first.sha256, "fixture"),
    /TEE_WORKLOAD_PIN_REJECTED/,
  );
});

import {
  guardPrivatemodeWire,
  ENCRYPTED_BODY,
} from "../packages/privatemode/src/wire.js";
test("unattested gateway never accepts a plaintext content body, downgrade or rerouted model", () => {
  const headers = {
    authorization: "Bearer fixture-key",
    "content-type": "application/json",
  };
  const request = (url: string, extra = {}) =>
    new Request(url, {
      method: "POST",
      headers: { ...headers, ...extra },
      body: '{"messages":[{"content":"private prompt"}]}',
    });
  assert.throws(
    () =>
      guardPrivatemodeWire(
        request("https://api.privatemode.ai/v1/chat/completions"),
        "gpt-oss-120b",
        "fixture-key",
        true,
      ),
    /TEE_REQUEST_REJECTED/,
  );
  assert.throws(
    () =>
      guardPrivatemodeWire(
        request("http://api.privatemode.ai/v1/chat/completions"),
        "gpt-oss-120b",
        "fixture-key",
        true,
      ),
    /TEE_REQUEST_REJECTED/,
  );
  assert.throws(
    () =>
      guardPrivatemodeWire(
        request("https://api.privatemode.ai/v1/chat/completions", {
          "content-type": ENCRYPTED_BODY,
          "privatemode-target-model": "other",
          "privatemode-oae-request-header": ":AAAA:",
        }),
        "gpt-oss-120b",
        "fixture-key",
        true,
      ),
    /TEE_REQUEST_REJECTED/,
  );
});

import { createPrivatemodeProvider } from "../packages/privatemode/src/index.js";
test("only policies admitting A2/H3/G3/X3 expose the versioned tool-chat catalog; stricter dispatch never bootstraps", async () => {
  for (const policy of [
    "public-builds,egress=metadata",
    "public-builds-trust-host",
    "trust-provider",
    "trust-provider-and-host,host=current",
    "trust-provider-and-host,code=fixed-private,host=outdated-firmware",
    "trust-provider-and-host,code=fixed-private,host=outdated-firmware,gpu=gaps",
    "trust-provider-and-host,code=fixed-private",
  ]) {
    let requests = 0;
    const adapter = createPrivatemodeProvider({
      policy,
      networkFetch: async () => {
        requests++;
        throw Error("network must not run");
      },
      recordAdmission: async () => undefined,
    });
    await adapter.initializeCatalog();
    const admitted = policy === "trust-provider-and-host,code=fixed-private";
    assert.equal(adapter.provider.getModels().length, admitted ? 3 : 0, policy);
    if (!admitted) {
      const result = await adapter.provider
        .streamSimple(
          { id: "gpt-oss-120b", provider: "privatemode" } as any,
          normalizeContext({ messages: [] }),
          { apiKey: "fixture-key" },
        )
        .result();
      assert.equal(result.stopReason, "error");
      assert.equal(requests, 0);
    }
  }
});
test("a manifest whose adoption record cannot be saved never sends credentials", async () => {
  let requests = 0;
  const adapter = createPrivatemodeProvider({
    policy: "trust-provider-and-host,code=fixed-private",
    recordAdmission: async () => {
      throw Error("disk full");
    },
    networkFetch: async () => {
      requests++;
      throw Error("network");
    },
  });
  await adapter.initializeCatalog();
  const result = await adapter.provider
    .streamSimple(
      adapter.provider.getModels()[0]!,
      normalizeContext({ messages: [] }),
      { apiKey: "fixture-key" },
    )
    .result();
  assert.equal(result.stopReason, "error");
  assert.equal(requests, 0);
});
test("unverified Coordinator assertions and complete-looking GPU metadata cannot raise a route", async () => {
  const adapter = createPrivatemodeProvider({
    policy: "trust-provider-and-host,code=fixed-private",
    recordAdmission: async () => undefined,
    networkFetch: async () =>
      Response.json({
        AttestationDoc: Buffer.from(
          JSON.stringify({ host: 1, gpu: 1, cpuVerified: true }),
        ).toString("base64"),
      }),
  });
  await adapter.initializeCatalog();
  const result = await adapter.provider
    .streamSimple(
      adapter.provider.getModels()[0]!,
      normalizeContext({
        messages: [{ role: "user", content: "synthetic prompt", timestamp: 1 }],
      }),
      { apiKey: "fixture-key" },
    )
    .result();
  assert.equal(result.stopReason, "error");
  assert.equal(adapter.getReport().routeDecisions?.[0]?.accepted, false);
});

import { Worker } from "node:worker_threads";
test("actual SDK encrypts every prompt/tool/reasoning content field and rejects plaintext response bytes", async () => {
  const sentinels = [
    "PRIVATE_USER_PROMPT",
    "PRIVATE_REASONING",
    "PRIVATE_TOOL_RESULT",
    "PRIVATE_TOOL_DESCRIPTION",
    "PRIVATE_TOOL_ARGUMENT",
  ];
  const worker = new Worker(
    new URL("./fixtures/privatemode-encryption-worker.mjs", import.meta.url),
    {
      workerData: {
        body: {
          model: "gpt-oss-120b",
          stream: true,
          messages: [
            { role: "user", content: sentinels[0] },
            {
              role: "assistant",
              content: "",
              reasoning_content: sentinels[1],
              tool_calls: [
                {
                  id: "c1",
                  type: "function",
                  function: {
                    name: "echo",
                    arguments: JSON.stringify({ value: sentinels[4] }),
                  },
                },
              ],
            },
            { role: "tool", tool_call_id: "c1", content: sentinels[2] },
          ],
          tools: [
            {
              type: "function",
              function: {
                name: "echo",
                description: sentinels[3],
                parameters: { type: "object" },
              },
            },
          ],
        },
      },
    },
  );
  const messages: any[] = [];
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(Error("fixture timeout")), 30000);
    worker.on("error", reject);
    worker.on("message", (m) => {
      messages.push(m);
      if (m.kind === "rejected" || m.kind === "accepted") {
        clearTimeout(timer);
        resolve();
      }
    });
  }).finally(() => worker.terminate());
  const wire = messages.find((m) => m.kind === "wire");
  assert.ok(wire);
  const headers = new Headers(wire.headers);
  assert.equal(headers.get("content-type"), ENCRYPTED_BODY);
  const across =
    JSON.stringify(wire.headers) + Buffer.from(wire.bytes).toString();
  for (const sentinel of sentinels)
    assert.equal(across.includes(sentinel), false);
  assert.equal(
    messages.some((m) => m.kind === "chunk"),
    false,
  );
  assert.equal(messages.at(-1).kind, "rejected");
});

import { mkdtemp, readFile, rm } from "node:fs/promises";
import { resolve } from "node:path";
import {
  manifestRecorder,
  createRecordedCdnManifestPolicy,
} from "../packages/privatemode/src/manifest.js";
test("explicit CDN admission records every adopted change before returning and fails closed on logging or redirects", async () => {
  const events: string[] = [];
  let revision = 0;
  const policy = createRecordedCdnManifestPolicy({
    fetch: async (input, init) => {
      assert.equal(
        String(input),
        "https://cdn.confidential.cloud/privatemode/v2/manifest.json",
      );
      assert.equal(init?.redirect, "error");
      assert.equal(init?.headers, undefined);
      return Response.json({ Policies: {}, revision: revision++ });
    },
    record: async (manifest) => {
      events.push(manifest.sha256);
    },
  });
  const first = await policy.admit(AbortSignal.timeout(1000));
  assert.equal(events[0], first.sha256);
  const second = await policy.admit(AbortSignal.timeout(1000));
  assert.equal(events[1], second.sha256);
  assert.notEqual(first.sha256, second.sha256);
  const broken = createRecordedCdnManifestPolicy({
    fetch: async () => Response.json({ Policies: {} }),
    record: async () => {
      throw Error("disk full");
    },
  });
  await assert.rejects(broken.admit(AbortSignal.timeout(1000)), /disk full/);
  const redirected = createRecordedCdnManifestPolicy({
    fetch: async () => new Response("{}", { status: 302 }),
    record: async () => assert.fail("must not record"),
  });
  await assert.rejects(
    redirected.admit(AbortSignal.timeout(1000)),
    /TEE_WORKLOAD_PIN_REJECTED/,
  );
});
test("manifest policy transitions are recorded before adoption and contain only authority metadata", async () => {
  const dir = await mkdtemp(resolve(".scratch/work/manifest-record-"));
  try {
    const path = resolve(dir, "adoptions.jsonl");
    const record = manifestRecorder(path);
    const signal = AbortSignal.timeout(1000);
    await record(
      { bytes: new Uint8Array(), sha256: "a".repeat(64), source: "pin:a" },
      signal,
    );
    await record(
      { bytes: new Uint8Array(), sha256: "a".repeat(64), source: "pin:a" },
      signal,
    );
    await record(
      { bytes: new Uint8Array(), sha256: "b".repeat(64), source: "pin:b" },
      signal,
    );
    const rows = (await readFile(path, "utf8"))
      .trim()
      .split("\n")
      .map((row) => JSON.parse(row));
    assert.equal(rows.length, 2);
    assert.equal(rows[1].previous, "a".repeat(64));
    assert.equal(rows[1].sha256, "b".repeat(64));
    assert.deepEqual(Object.keys(rows[1]).sort(), [
      "adoptedAt",
      "previous",
      "sha256",
      "source",
      "version",
    ]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test("native catalog refresh uses the configured credential, filters non-tool models and cannot create new admitted models", async () => {
  let catalogRequests = 0;
  const adapter = createPrivatemodeProvider({
    policy: "trust-provider-and-host,code=fixed-private",
    networkFetch: async (input, init) => {
      const request = new Request(input, init);
      assert.equal(request.url, "https://api.privatemode.ai/v1/models");
      assert.equal(
        request.headers.get("authorization"),
        "Bearer stored-fixture-key",
      );
      catalogRequests++;
      return Response.json({
        data: [
          { id: "glm-5.3", tasks: ["generate", "tool_calling"] },
          { id: "gpt-oss-120b", tasks: ["generate"] },
          { id: "attacker-model", tasks: ["generate", "tool_calling"] },
        ],
      });
    },
  });
  await adapter.initializeCatalog();
  await adapter.provider.refreshModels!({
    credential: { type: "api_key", key: "stored-fixture-key" },
    signal: AbortSignal.timeout(1000),
    allowNetwork: true,
    force: true,
    publish: async (publication) => {
      publication.update?.();
      return true;
    },
  });
  assert.equal(catalogRequests, 1);
  assert.deepEqual(
    adapter.provider.getModels().map((m) => m.id),
    ["glm-5.3"],
  );
});
