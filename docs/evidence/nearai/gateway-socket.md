# NEAR gateway socket

Observed 2026-10-09 (about 16:00–16:40 UTC) from macOS with `@nearai/inference-sdk` 0.1.0, against the branch that moved the gateway route onto an owned connection (parent [8fa6451](https://github.com/ariofrio/pi-tee/commit/8fa6451)). Model `z-ai/glm-5.3-flash`, policy `trust-provider-and-host`. The route rating is unchanged at A3/G3/X3 with H1/H2 per request.

## What the SDK connection did not establish

NEAR's Node SDK opens a new `node:https` connection for each request (`agent: false`), each pinned only to the gateway quote's SPKI. Gateway evidence, model evidence, the sealed request and the signature lookup could therefore reach different gateway processes that hold the same key. The SDK path also required `node:https` socket capture, which Bun does not provide, so the route refused Bun.

## Live observations

- With `createNearProvider({ route: "gateway" })`, one synthetic request completed with `stop` and the text `OK` under Node 26.10.0 and Bun 1.3.13. Both reported `near-gateway: A3 H2 G3 X3`: of the two checked quotes, one was Intel `OutOfDate` (TDX TCB SVN `0b0103…`) and one `UpToDate` (`0b0104…`).
- With `node:tls.connect` and `node:https.request` instrumented after catalog load, the Node dispatch opened one TLS connection to `cloud-api.near.ai` and no `https.request`. The other connections went to Intel's PCS collateral hosts. NRAS was not contacted.
- Twelve fresh-nonce gateway reports sampled on 2026-10-09 all named one instance, TLS SPKI `73862c25…a5ad` and one signer. On 2026-10-07, [two distinguishable instances](near-gateway-evidence.json) presented the same TLS SPKI and signer, so the socket binding authenticates a key holder, not one gateway instance.
- The tests [near-direct-channel.test.ts](../../../tests/near-direct-channel.test.ts) and [near-gateway.test.ts](../../../tests/near-gateway.test.ts) check that the gateway scope admits only one model's metadata and evidence and inference only after approval, and that failed appraisal sends no inference and approves nothing. The recorded gateway report is [the test fixture](../../../tests/fixtures/near-gateway-attestation.json).

## Limits

NEAR's gateway requires the API key on its evidence endpoint, so the key reaches the WebPKI-authenticated gateway before the quote is appraised; request bodies still wait for approval. The gateway decrypts OHTTP and forwards to model workers over its own connections. No Bun-compiled Pi suite has been run on this route.
