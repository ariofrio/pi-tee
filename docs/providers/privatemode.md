# Privatemode

Load `packages/privatemode/dist/extension.js` from the [locked checkout](../quick-start.md), then `/login privatemode`. The API-key fallback is `PRIVATEMODE_API_KEY`. The proxyless API is excluded.

## Admission and trust

The route is A2/H3/G3/X3, admitted most tightly by `trust-provider-and-host,code=fixed-private`. Exact manifest/policy pins cover every deployment-key recipient, including other workloads sharing the secret. Fresh Coordinator authentication does not establish fresh serving-worker CPUs or complete GPU coverage. Operator-readable container logs and raw OTLP forwarding to an unattested collector prevent a metadata-only handling claim. A reproduced subset of images cannot establish an A1 serving closure.

Every request uses an isolated hash-checked SDK 1.58.0 verifier, fresh nonce and authenticated mesh CA/secret exchange. Unknown/case-aliased fields, byte-different manifests and extra/omitted/duplicated policies fail before key exchange. Only then is the complete chat JSON encrypted and each response frame authenticated. No cached quote/secret extends admission. There is one inference send, without mismatch re-fetch, rotation recovery or fallback. [Implementation/source investigation and dated negatives](../evidence/providers/privatemode-validation.md).

## Manifest admission

`PI_PRIVATEMODE_MANIFEST_MODE=hard-pin` is the default. The shipped manifest is [v1.58.0](../../packages/privatemode/manifests/v1.58.0.json), SHA-256 `384a2137e534357d74392bf3940373ff49d309d91551376b5a7f828e372af42b`. Every different manifest is rejected, even if the provider publishes it. Set `PI_PRIVATEMODE_MANIFEST_PATH` to choose another local manifest; its bytes are captured once per provider instance and held immutable. Restart to adopt a changed file.

Explicit `PI_PRIVATEMODE_MANIFEST_MODE=logged-cdn` instead authorizes pi-tee to fetch [the CDN manifest](https://cdn.confidential.cloud/privatemode/v2/manifest.json) for each request and adopt its exact bytes only after saving the change record. It cannot be combined with a local path. This trusts Privatemode's CDN to choose each new private-code pin; it does not establish a public release, reproduction or review approval. Fetch or recording failure blocks the request. The SDK's high-level client and its automatic mismatch re-fetch are never used in either mode.

Adoptions append digest, previous digest, source and timestamp to `$XDG_STATE_HOME/pi-tee/privatemode/manifest-admissions.jsonl` (default `~/.local/state`). No credential, prompt or quote is recorded. New directories/files use modes 700/600.

## Plaintext and metadata

| Party | Data available |
| --- | --- |
| Local OS/runtime, Pi, extensions and tools | Credentials and conversation plaintext; these remain trusted. |
| Ordinary WebPKI gateway `api.privatemode.ai` | Bearer API key, URL/path, model header, client/version, secret ID, request ID, salted content-derived shard keys, estimated content tokens when supplied, OAE exchange header, runtime-added User-Agent/accept-* headers, ciphertext size, timing and source IP. The chat JSON body and response body stay encrypted. Catalog requests expose the API key and requested path. |
| Bootstrap gateway | Fresh nonce, attestation evidence, manifest/policy hashes, mesh certificates, client ephemeral public key, encapsulated key and exchange signature, in addition to credential and traffic metadata. No chat content is supplied to bootstrap. |
| Intel/AMD collateral endpoints | Certificate/platform identifiers and request timing, without API credentials or conversation content. |
| Manifest-admitted key holders | Decrypted conversation, tools, reasoning and response bytes: secret service, inference proxies/engines, GPU devices and other admitted workloads able to obtain the shared deployment secret. Privatemode, its serving hosts and the admitted code's custody/recovery behavior remain trusted. |
| Operators and telemetry collectors | Container logs are readable and the OTLP relay can forward arbitrary raw payloads. Deployed retention, training, logging and egress behavior are unverified; X3 makes no content-free export guarantee. |
| CDN, in logged-CDN mode only | Manifest GET, timing and source IP; no API credential or conversation content. |

The gateway uses hostname-verified WebPKI HTTPS with the platform's TLS 1.2+ default, redirect rejection and fixed paths. Prompt encryption authenticates an attested key before any content crosses that hop. This follows the owner's explicit credential/metadata exception; the ordinary gateway is not an attested plaintext endpoint. No NRAS calls occur, including with `verifier=nras`.

## Models and reasoning

The shipped tool-chat snapshot contains `glm-5.3`, `glm-5.3-flash` and `gpt-oss-120b`. Credentialed `/privatemode models refresh` admits only those IDs with generation/tool support; aliases and specialized endpoints are excluded. GLM context is one million tokens, GPT 131,072; prices are unavailable. These are catalog claims.

Reasoning-off/minimal selects low effort because these effort-only APIs do not disable reasoning. GLM low maps to low, medium/high to high, xhigh to max. GPT supports low/medium/high. See the source links in the [validation record](../evidence/providers/privatemode-validation.md#source-evidence).

Use the [shared commands](../reference/commands-settings.md) and [payload/lifetime limits](../reference/support-limits.md). Cancellation terminates workers and readers; it does not prove remote generation stopped. Retention/training/audit commitments have not been appraised and do not gate admission. [Live procedure](../procedures/live-validation.md).
