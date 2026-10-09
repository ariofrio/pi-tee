# Tinfoil

Load `packages/tinfoil/dist/extension.js` from the [locked checkout](../quick-start.md), then `/login tinfoil`. The API-key environment fallback is `TINFOIL_API_KEY`.

## Public workers

Public admission covers `gemma4-31b`, `deepseek-v4-1-flash` and `glm-5-3` when the live catalog and workers qualify. Current protected workers can meet the default `public-builds,egress=metadata`. [Admission table](../providers.md), [exact publisher/manufacturer and key-custody contract](../contracts/tinfoil-public-builds.md).

Every dispatch freshly appraises CPU evidence, public guest/workload/container/runtime inputs, quote-bound serving keys, declared serving-GPU coverage and applicable hardware checks. Authenticated compatible releases from the named workflows update automatically without maintained deployment pins; B3/S3 is neither independent reproduction nor per-release review.

Genoa below local floors can be H2 while preserving publisher minima, revocation, nonce/key binding and production restrictions. Intel `OutOfDate` public workers are rejected under every policy by the pinned verifier. G2 authenticated gaps need explicitly admitting thresholds; `gpu=unchecked` skips GPU appraisal and rates G3. Local is the default; NRAS uses the same GPU rules with added service trust. [Hardware rules](../reference/hardware-policy.md).

Direct checks the appraised SPKI on the actual TLS 1.3 socket before credentials/ciphertext. That quote-bound key replaces WebPKI endpoint authorization. The encrypted transport sends once, rejects reconnect/resend and rechecks admission after hooks and at TLS handoff.

## Billing gateway

DeepSeek and GLM can use `inference-gateway.tinfoil.sh` only when no direct worker qualifies; Gemma is excluded. Untrusted catalog/relay delivery supplies routing hints and nonce-bound evidence, never software or key authority. The same full worker appraisal establishes levels. Direct is preferred because fewer parties receive credentials/metadata.

The unattested WebPKI TLS 1.3 gateway receives the API key, model, headers and worker host. Inference names the worker through `X-Tinfoil-Model`, `X-Tinfoil-Seal` and `X-Tinfoil-Enclave-Url`; EHBP seals the complete body to its own appraised HPKE key. The seal is routing, not cryptographic host authorization. Another worker cannot decrypt it or authenticate a substituted response. The gateway is not a new plaintext recipient.

A 412 means the sealed worker is unavailable and is terminal: no reroute, re-appraisal or resend. A later request starts with fresh evidence/sealing under the same policy. Non-200 responses, redirects, rotation errors and dropped connections also fail. `/tinfoil status` discloses credential recipients, preference/failure reasons and the strongest rejected gateway worker's levels/failing axes.

EHBP authenticates individual frames but has no authenticated end marker. The gateway can truncate at a frame boundary: Pi detects a missing completion `finish_reason`, while trailing usage can vanish silently. EHBP also has no anti-replay: the relay can replay a sealed request to the same worker, causing duplicate inference/billing and an authentic duplicate response. Client send-once cannot prevent relay replay. Billing truthfulness and availability are outside the contract. [Pinned protocol investigation and Node/Bun validation](../evidence/tinfoil/gateway-validation.md).

## Router

The router requires `trust-provider-and-host` and remains A3/H3/G3/X3, counting hidden workers and sidecars. pi-tee appraises it without Tinfoil's SDK, using the same WASM verifier as public direct workers. Before each dispatch it fetches `inference.tinfoil.sh` evidence under a fresh client nonce and checks the manufacturer's collateral and revocation, the production platform policy and pi-tee's firmware floors. It then authenticates the router's tagged release from `tinfoilsh/confidential-model-router` through its public workflow on GitHub-hosted runners. That identity admits only the router; it is never accepted as a model publisher. Router firmware below local floors is admitted only by policies that allow `host=outdated-firmware` or weaker; the route-wide H3 keeps `host=current` from admitting it at all.

The request is sealed to the attested HPKE key and sent once over TLS pinned to the attested key. A key rotation, a different backend behind the same name or any other failure ends the dispatch without re-appraisal or resend. The router decrypts every request and selects workers whose code, CPU and GPU evidence never reach the client. It cannot establish downstream software, key custody, GPU protection or handling, and web-search paths can expose plaintext. [Router appraisal record](../evidence/tinfoil/router-appraisal.md).

## Limits and diagnosis

A fresh random encrypted `cache_salt` is generated per public dispatch. This defeats cross-turn prompt caching and can increase prefill work and cost. Per-request caching is a privacy choice, not a billing guarantee.

Public workers are rediscovered/appraised per request. Delivery can withhold candidates or close ingress; no availability promise is made. Authenticated immutable caching does not extend fresh CPU/GPU/key/witness checks. [Limits](../reference/support-limits.md), [storage](../reference/commands-settings.md), [required serving contract](../contracts/tinfoil-public-builds.md).

Tinfoil commitments have not been reviewed and do not gate admission. Historical router-only model/configuration findings and independent implementation reviews remain in the [design snapshot](../evidence/client/2026-10-09-design-assessment.md#provider-assessment) and [review archive](../archive/reviews/README.md). Use the live catalog rather than historical model availability statements.
