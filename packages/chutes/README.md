# pi-chutes

Chutes provider for Pi with native API-key login, confidential tool-capable chat discovery, encrypted streaming, reasoning and cancellation. Packages are unpublished; use the locked Node 24 checkout with Pi 1.0.4. Bun 1.3.13 runs the same adapter.

```sh
npm ci --ignore-scripts
npm run check
PI_TEE_POLICY=trust-provider-and-host,host=current pi -e ./packages/chutes/dist/extension.js
```

Use `/login chutes`; Pi's stored key takes precedence over `CHUTES_API_KEY`. `/logout chutes` uses Pi's credential store. `/chutes status` shows policy, actual request levels, trusts, gaps and transport disclosures. `/chutes policy <position>[,axis=value…]` changes this provider's policy for the session and aborts active requests. `/chutes models` lists discovery; `/chutes models refresh` refreshes it.

## Admission

Each request obtains a new random client nonce and authenticates the selected instance's Intel TDX quote locally against Intel's production root, signed collateral, validity and revocation data. The quote commits to `SHA256(nonce_hex + e2e_pubkey_base64)` and the host certificate's DER SPKI hash. That certificate verifies the signed evidence envelope, which must contain the same nonce, quote and GPU list. The instance's discovered ML-KEM-768 key must match that quote before any content is sent. [Evidence appraisal](src/evidence.ts), [instance selection](src/transport.ts), [security model](../../docs/security-model.md).

The route is **A3/G3/X3**. H is **H1** when fresh authenticated evidence is `UpToDate` and meets the shared TDX component SVN and platform/QE collateral-edition floors; otherwise supported fresh `OutOfDate` or below-floor evidence is **H2**. Stale, unbound, malformed, debug, service-TD and unsupported CPU evidence are rejected. This adapter supports TDX v4 only; no SNP path is offered. With H1, the tightest admitting policy is `trust-provider-and-host,host=current`. With H2 it is `trust-provider-and-host,host=outdated-firmware`.

Chutes' runtime and key custody are not authenticated to a fixed or public release, so software remains A3. Provider-assembled GPU evidence cannot prove the full serving set under A3, so GPUs remain G3 even if individual reports are genuine. Egress and storage restrictions are unverified, so handling is X3. The provider and host are trusted. Catalog declarations, public source and provider commitments never raise a level. No GPU reports are sent to NRAS.

The client verifies the first encrypted recipient, not a closed plaintext-serving implementation. Chutes-controlled code can forward plaintext or release keys to other components without client-visible evidence; the client cannot establish their host or software properties. Those gaps remain disclosed under A3/G3/X3. A client transport cannot enforce a provider's internal behavior.

## Content and metadata

The complete guarded Chat Completions JSON body is gzip-compressed and encrypted to the freshly authenticated instance key, using ML-KEM-768, HKDF-SHA256 and ChaCha20-Poly1305. This includes messages, tool definitions and results, reasoning controls and the client's ephemeral response public key. The public API relays ciphertext. Response content is decrypted only after AEAD authentication. A new response key is generated for every request; replayed chunks and incomplete streams are rejected. [Transport](src/transport.ts), [encryption](src/crypto.ts), [official protocol](https://github.com/chutesai/e2ee-proxy/tree/e213a090cb82be3b4556ce0f2fbd912406001477).

The ordinary, hostname-verified WebPKI endpoints see these fields:

| Endpoint | Credential and metadata |
| --- | --- |
| `llm.chutes.ai/v1/models` | Public catalog GET, ordinary HTTP transport headers, client IP and timing; no API key or request content. |
| `api.chutes.ai/e2e/instances/<chute ID>` | `Authorization: Bearer <API key>`, chute ID, `Accept`, `Cache-Control`, transport headers, client IP and timing. Returns instance keys and single-use invocation tokens. |
| `api.chutes.ai/chutes/<chute ID>/evidence?nonce=<challenge>` | Chute ID and fresh client nonce, `Accept`, `Cache-Control`, transport headers, client IP and timing; no API key or request content. |
| `api.chutes.ai/e2e/invoke` | API key in `Authorization`; `X-Chute-Id`, `X-Instance-Id`, `X-E2E-Nonce` (invocation token), `X-E2E-Stream`, `X-E2E-Path`, `Content-Type`; transport headers, encrypted sizes, client IP and timing. No plaintext prompt, tool or reasoning fields. |

Invocation additionally sends `Host`, `Content-Length` and `Connection: close`; discovery and catalog requests use runtime-generated transport headers, including encoding and user-agent where applicable. Caller headers and session-affinity fields are not forwarded. The public API's TLS key is **not attested**; Invocation owns a hostname-verified WebPKI TLS 1.3 socket and sends exactly one HTTP request, including after HTTP 421; discovery and catalog use the runtime's normal WebPKI verification and minimum version without downgrade. The API can associate a chute ID with its model and account. Provider billing counters outside response encryption are not enclave-authenticated; only numeric token counters are passed through. The relay remains trusted for stream ordering, billing and availability. Chutes and its selected runtime receive decrypted content; its subsequent handling is unverified. Intel PCS sees collateral lookups and their timing.

An invocation token and attestation session expire before dispatch. The transport sends once, rejects redirects and refuses resend or replacement-key recovery. Failures never use a plaintext API or weaker route. Cancellation aborts local work and network reads; it does not prove remote generation has stopped.

## Validation

`npm run check`, `npm run smoke`, and `npm run smoke:packages` cover policy/transport behavior and native loading/login. Chutes tests run under Node and Bun in CI. Cryptographic envelope, encryption and negative dispatch tests use synthetic keys/evidence; those tests do not qualify a live deployment. The saved private evidence test requires `CHUTES_TEST_EVIDENCE_DIR` and checks actual Intel signatures and host-envelope/key bindings. [Validation record](../../docs/chutes-validation.md).

The opt-in live Pi suite uses capped synthetic prompts and an isolated credential store. Load credentials only for the command:

```sh
PI_TEE_POLICY=trust-provider-and-host,host=current node --env-file=/path/to/private/chutes.env \
  --import tsx scripts/live-pi.ts chutes Qwen/Qwen3.8-27B-TEE
PI_TEE_POLICY=trust-provider-and-host,host=current bun --env-file=/path/to/private/chutes.env \
  scripts/live-pi.ts chutes Qwen/Qwen3.8-27B-TEE
```

`scripts/live-chutes-attestation.ts` checks per-model CPU/key evidence with discovery credentials but sends no inference. Live results are observations of sampled instances, not permanent model ratings. The extension protects its own requests; other Pi providers, tools and extensions remain trusted local code.
