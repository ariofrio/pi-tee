# pi-privatemode

Privatemode extension for Pi 1.0.4, using the encrypted-body API and the hash-checked `privatemode-ai` 1.58.0 verifier. Supports native API-key login, streamed text/reasoning, tools, usage and cancellation under Node 24+ and Bun. The proxyless API is excluded. The package is unpublished.

## Setup and policy

Build the locked workspace, then start Pi:

```sh
npm ci --ignore-scripts
npm run check
PI_TEE_POLICY=trust-provider-and-host,code=fixed-private \
  node_modules/.bin/pi -e packages/privatemode/dist/extension.js
```

Use `/login privatemode` or `PRIVATEMODE_API_KEY`. Pi's stored key takes precedence; `/logout` removes it. `/privatemode status` reports the last request's authenticated observations and trust assumptions. `/privatemode policy <setting>` changes only this provider and aborts its active requests.

Successful requests rate **A2/H3/G3/X3**. The tightest admitting policy is `trust-provider-and-host,code=fixed-private`; bare `trust-provider-and-host` also admits them. The default public-build policy and policies requiring fresh serving CPUs or verified GPUs admit no models and send no content. Catalog claims never raise levels.

For every request, a fresh isolated verifier authenticates a 32-byte client nonce, the Coordinator's hardware evidence, the exact admitted manifest and its complete policy set, and the mesh CA bound to that evidence. The secret exchange authenticates the certificate chain and signature binding the fresh client key exchange. Only then does the SDK encrypt the complete chat JSON and authenticate encrypted response frames. There is one inference send, with no rotation resend or weaker fallback. Admission expires after 60 seconds before dispatch; response bytes remain bounded. [Design and evidence](../../docs/privatemode.md).

H3 counts every plaintext/key recipient, including the secret service and other workloads sharing the deployment secret. Their CPU freshness and firmware floors are unverified by the client. The observed Coordinator's SNP build 1 is below pi-tee's Genoa minimum 21. Complete, client-fresh GPU coverage is unavailable, so G3 remains. Container logs are operator-readable, and the OTLP relay forwards raw bodies to an unattested collector without allowlisting payload fields. These limits, and code below A1, require X3; this provider makes no H1 or metadata-only handling claim.

## Manifest admission

`PI_PRIVATEMODE_MANIFEST_MODE=hard-pin` is the default. The shipped manifest is [v1.58.0](manifests/v1.58.0.json), SHA-256 `384a2137e534357d74392bf3940373ff49d309d91551376b5a7f828e372af42b`. Every different manifest is rejected, even if the provider publishes it. Set `PI_PRIVATEMODE_MANIFEST_PATH` to choose another local manifest; its bytes are captured once per provider instance and held immutable. Restart to adopt a changed file.

Explicit `PI_PRIVATEMODE_MANIFEST_MODE=logged-cdn` instead authorizes pi-tee to fetch [the CDN manifest](https://cdn.confidential.cloud/privatemode/v2/manifest.json) for each request and adopt its exact bytes only after saving the change record. It cannot be combined with a local path. This trusts Privatemode's CDN to choose each new private-code pin; it does not establish a public release, reproduction or review approval. Fetch or recording failure blocks the request. The SDK's high-level client and its automatic mismatch re-fetch are never used in either mode.

Adoptions append digest, previous digest, source and timestamp to `$XDG_STATE_HOME/pi-tee/privatemode/manifest-admissions.jsonl` (default `~/.local/state`). No credential, prompt or quote is recorded. New directories/files use modes 700/600. `ManifestAdmissionPolicy.admit(signal)` is the library seam for a reproduced pin or public-log policy; the provider rehashes returned bytes and records admission before bootstrap. `createRecordedCdnManifestPolicy`, `createPinnedManifestPolicy` and `manifestRecorder` are exported. A new policy cannot promote the baseline above A2 without a separate verified release/closure implementation.

## Plaintext and metadata

| Party | Data available |
| --- | --- |
| Local OS/runtime, Pi, extensions and tools | Credentials and conversation plaintext; these remain trusted. |
| Ordinary WebPKI gateway `api.privatemode.ai` | Bearer API key, URL/path, model header, client/version, secret ID, request ID, salted content-derived shard keys, estimated content tokens when supplied, OAE exchange header, ciphertext size, timing and source IP. The chat JSON body and response body stay encrypted. Catalog requests expose the API key and requested path. |
| Bootstrap gateway | Fresh nonce, attestation evidence, manifest/policy hashes, mesh certificates, client ephemeral public key, encapsulated key and exchange signature, in addition to credential and traffic metadata. No chat content is supplied to bootstrap. |
| Intel/AMD collateral endpoints | Certificate/platform identifiers and request timing, without API credentials or conversation content. |
| Manifest-admitted key holders | Decrypted conversation, tools, reasoning and response bytes: secret service, inference proxies/engines, GPU devices and other admitted workloads able to obtain the shared deployment secret. Privatemode, its serving hosts and the admitted code's custody/recovery behavior remain trusted. |
| Operators and telemetry collectors | Container logs are readable and the OTLP relay can forward arbitrary raw payloads. Deployed retention, training, logging and egress behavior are unverified; X3 makes no content-free export guarantee. |
| CDN, in logged-CDN mode only | Manifest GET, timing and source IP; no API credential or conversation content. |

The gateway uses hostname-verified WebPKI HTTPS with the platform's TLS 1.2+ default, redirect rejection and fixed paths. Prompt encryption authenticates an attested key before any content crosses that hop. This follows the owner's explicit credential/metadata exception; the ordinary gateway is not an attested plaintext endpoint. No NRAS calls occur, including with `verifier=nras`.

## Models and validation

The shipped tool-chat catalog contains `glm-5.3`, `glm-5.3-flash` and `gpt-oss-120b`. `/privatemode models refresh` uses the native stored credential to refresh `/v1/models`, restricting results to those IDs and requiring generation/tool support. Aliases and specialized endpoints are excluded. GLM has a one-million-token context, GPT 131,072; prices are labeled unavailable. Reasoning-off selects low effort for all three models because the documented API does not offer disabling reasoning. GLM low maps to low, medium/high to high and xhigh to max. GPT minimal maps to low, with low/medium/high supported. `PI_TEE_OFFLINE=1` skips startup discovery; it does not permit offline attestation or inference.

```sh
# Authenticated attestation/key negatives, zero inference:
PI_PRIVATEMODE_LIVE=1 node --env-file=/path/to/private/privatemode.env \
  --import tsx --test tests/privatemode-live.test.ts

# Capped synthetic completion, tools, reasoning and cancellation:
PI_TEE_POLICY=trust-provider-and-host,code=fixed-private \
  node --env-file=/path/to/private/privatemode.env --import tsx \
  scripts/live-pi.ts privatemode gpt-oss-120b
# Bun reads TypeScript directly; use bun --env-file=... scripts/live-pi.ts ...
```

The live suites require a key for catalog, attestation, secret exchange and inference; bootstrap attestation itself requires authentication. The CDN is public. Ordinary CI needs no key: it covers hard-pin/logged adoption, policy rejection, firmware floors, the real SDK's encrypted-content boundary and rejection of plaintext responses. Live tests additionally cover nonce substitution, mesh-key substitution, stale replay, an extra closure component and a swapped secret-exchange signature. [Validation record](../../docs/privatemode.md#validation).

These protections cover this provider's requests. Other providers, compaction, local tools and extensions can transmit plaintext independently.

Written by Codex.
