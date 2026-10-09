# Chutes

Load `packages/chutes/dist/extension.js` from the [locked checkout](../quick-start.md), then `/login chutes`. The API-key fallback is `CHUTES_API_KEY`.

## Admission and trust

The instance-key route is A3/G3/X3, with fresh H1/H2 from [shared TDX floors](../reference/hardware-policy.md#intel-tdx). The tightest H1 policy is `trust-provider-and-host,host=current`; supported H2 instances need `host=outdated-firmware`. Only Intel TDX v4 is offered; SNP, stale/unbound/malformed/debug/service-TD evidence fails. [Evidence appraisal](../../packages/chutes/src/evidence.ts).

Each request's nonce quote binds the selected ML-KEM-768 key and the SPKI that authenticates its signed envelope. The API TLS key is not inferred to be attested. Every candidate must qualify before encryption; rejected instances cannot promote another candidate or authorize content.

Software and key custody are unverified to a fixed/public release, so A3 remains. Provider-assembled GPU lists cannot establish complete serving coverage under A3, so G3 remains; no GPU reports go to NRAS. Egress/storage are unverified, so X3 remains. Chutes-controlled code can forward plaintext or release keys to unseen recipients; authentication of the first encrypted recipient cannot close its internal serving implementation. Provider commitments do not raise levels.

## Content and metadata

The complete guarded Chat Completions JSON body is gzip-compressed and encrypted to the freshly authenticated instance key, using ML-KEM-768, HKDF-SHA256 and ChaCha20-Poly1305. This includes messages, tool definitions and results, reasoning controls and the client's ephemeral response public key. The public API relays ciphertext. Response content is decrypted only after AEAD authentication. A new response key is generated for every request; replayed chunks and incomplete streams are rejected. [Transport](../../packages/chutes/src/transport.ts), [encryption](../../packages/chutes/src/crypto.ts), [official protocol](https://github.com/chutesai/e2ee-proxy/tree/e213a090cb82be3b4556ce0f2fbd912406001477).

Chutes' licensed E2EE clients are written in Python and Lua, and its browser test client (Rust compiled to WebAssembly) carries no license, so pi-tee implements the protocol with Noble primitives. [`npm run check:chutes-peer`](../../scripts/check-chutes-peer.ts) holds it to that browser client, [chutesai/e2ee-test](https://github.com/chutesai/e2ee-test/tree/0e3543180543c0c22637efb47a243d169ff0ab24), fetched by commit and SHA-256: both clients' requests open to the same payload, and each decrypts streams sealed to the other's response key.

The ordinary, hostname-verified WebPKI endpoints see these fields:

| Endpoint | Credential and metadata |
| --- | --- |
| `llm.chutes.ai/v1/models` | Public catalog GET, ordinary HTTP transport headers, client IP and timing; no API key or request content. |
| `api.chutes.ai/e2e/instances/<chute ID>` | `Authorization: Bearer <API key>`, chute ID, `Accept`, `Cache-Control`, transport headers, client IP and timing. Returns instance keys and single-use invocation tokens. |
| `api.chutes.ai/chutes/<chute ID>/evidence?nonce=<challenge>` | Chute ID and fresh client nonce, `Accept`, `Cache-Control`, transport headers, client IP and timing; no API key or request content. |
| `api.chutes.ai/e2e/invoke` | API key in `Authorization`; `X-Chute-Id`, `X-Instance-Id`, `X-E2E-Nonce` (invocation token), `X-E2E-Stream`, `X-E2E-Path`, `Content-Type`; transport headers, encrypted sizes, client IP and timing. No plaintext prompt, tool or reasoning fields. |

Invocation additionally sends `Host`, `Content-Length` and `Connection: close`; discovery and catalog requests use runtime-generated transport headers, including encoding and user-agent where applicable. Caller headers and session-affinity fields are not forwarded. The public API's TLS key is **not attested**. Invocation owns a hostname-verified WebPKI TLS 1.3 socket and sends exactly one HTTP request, including after HTTP 421; discovery and catalog use the runtime's normal WebPKI verification and minimum version without downgrade. The API can associate a chute ID with its model and account. Provider billing counters outside response encryption are not enclave-authenticated; only numeric token counters are passed through. The relay remains trusted for stream ordering, billing and availability. Chutes and its selected runtime receive decrypted content; its subsequent handling is unverified. Intel PCS sees collateral lookups and their timing.

Invocation-token and attestation expiry are checked before dispatch. The transport sends once, rejects redirects and refuses resend or replacement-key recovery. Failures never use a plaintext API or weaker route. Cancellation aborts local work and network reads; it does not prove remote generation has stopped.

## Discovery and diagnosis

Discovery admits declared confidential tool-chat models with an instance-discovery ID. There is no plaintext route or silent fallback. `/chutes status` reports current levels, trusts, gaps and transport disclosures. A listed model whose instances serve no evidence, such as `Qwen/Qwen3-235B-A22B-Thinking-2507-TEE` on 2026-10-09, stays listed and fails with `HTTP 400 evidence unavailable`; a 429 shows as `rate-limited`. [Diagnosis](../quick-start.md#diagnose-a-blocked-request). Use [shared commands](../reference/commands-settings.md) and [limits](../reference/support-limits.md).

[Credentialed validation and receipt matrix](../chutes-validation.md) distinguish accepted from rejected samples; they do not establish permanent model ratings. Real private evidence replay is separate from synthetic cryptographic tests. [Qualification procedure](../procedures/live-validation.md).
