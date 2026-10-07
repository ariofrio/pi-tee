# Pi NEAR AI and Tinfoil implementation

Date: 2026-10-07. Author: Codex. Scope: SDK-policy extensions and live Pi validation; independently approved production deployments remain gated.

Repository: [ariofrio/pi-tee](https://github.com/ariofrio/pi-tee). Initial integration: `7331cfd`; model visibility: `bc2cc98`.

The implementation is in [pi-tee](../README.md), with two independently installable extensions and a shared library:

| Package | Implementation |
| --- | --- |
| `pi-nearai` | [Native registration and commands](../packages/nearai/src/extension.ts), [SDK transport and runtime checks](../packages/nearai/src/index.ts), [catalog mapping](../packages/nearai/src/catalog.ts). |
| `pi-tinfoil` | [Native registration and commands](../packages/tinfoil/src/extension.ts), [EHBP SDK transport](../packages/tinfoil/src/index.ts), [catalog mapping](../packages/tinfoil/src/catalog.ts). |
| `pi-tee-core` | [Provider policy, native login and catalog refresh](../packages/core/src/provider.ts), [final serialized request guard](../packages/core/src/transport.ts), [response signature barrier](../packages/core/src/response.ts). This library is not another extension. |

The default `approved` policy hides inference models and rejects requests before SDK setup. No manifest, environment flag, or SDK success can bypass the absent deployment qualification. Explicit `sdk` policy enables the integrations with provider-specific trust assumptions and a report that marks independent approval, the closed trust set, and protected-session enforcement as unestablished. See [SECURITY.md](../SECURITY.md).

Both extensions use Pi's native API-key login and stored model-refresh APIs. Commands select policy, report status, show discovery and force refresh. Provider requests reuse Pi's OpenAI conversion, tools, reasoning and usage. The final transport fixes the endpoint/model/auth headers and rejects hosted tools, remote media and unclassified payload fields. Errors use fixed terminal codes and Pi provider retries are disabled. Tinfoil's default router retains the disclosed SDK rotation resend. Its explicit direct route owns EHBP and the attested TLS socket and sends once.

NEAR discovery additionally checks public per-model capability metadata in [`loadNearCatalog()`](../packages/nearai/src/discovery.ts). Its default TEE-only filter hides non-TEE and unknown models, using the SDK's `providerType: "vllm"` and `attestationSupported: true` selection rule with an exact model-ID match. This is an unverified provider claim. `PI_NEARAI_MODEL_VISIBILITY=all` or `/nearai models all` displays labeled blocked discoveries; `/nearai models tee` restores the filter. Showing models does not relax inference gates, and Approved policy still hides every picker model. [Visibility, cache and pre-send tests](../tests/near-visibility.test.ts) exercise this distinction.

NEAR requires Node 24 with the relevant TLS APIs, attested gateway TLS, OHTTP, model encryption, UpToDate CPU status, GPU evidence and a model-serving response signature. `authenticateResponse()` releases no body bytes before verification. Decrypted response bodies are capped at 8 MiB and pinned gateway network bodies at 32 MiB before SDK retention; these are body limits, not a total process-memory budget. Pi/Bun compatibility is not assumed.

## Validation

- Locked checkout: Node 24.21.0, Pi AI/coding-agent 1.0.4, NEAR SDK 0.1.0 and Tinfoil 1.2.2. Pi and SDK versions are exact pins. The root lockfile freezes transitive artifacts; fresh tarball installs may resolve a different dependency set.
- `npm run check`: build, package/test/script type checks and **35 passing tests**. [Tests](../tests/provider.test.ts) use the real Pi OpenAI adapter with controlled external transport responses, including payload overrides, hosted tools, retry classification, Unicode tool arguments, forged tool responses and cancellation. The rotation regression failed with a consumed `Request` and passes with reusable guarded bytes. A tool follow-up regression failed when Pi replayed `message.reasoning`; it now passes with text reasoning admitted, while a separate negative regression rejects structured reasoning before the external transport. This retains the SDK's disclosed resend policy rather than adding a Pi retry. [Refresh tests](../tests/refresh.test.ts) cover freshness, forced refresh, offline restoration, failure retention and generation-checked publications. [Response tests](../tests/response.test.ts) cover verification barriers, truncation/mixed identity, size limits and cancellation.
- `npm run smoke`: both compiled entries load through Pi's real resource loader; native API-key login works using synthetic credentials in an isolated store.
- `npm run smoke:packages`: both tarballs install and load independently outside the repository's module-resolution path, accept native login, and have no resolvable copy of the other provider's SDK. Required compiled entries, type declarations, README and license are included. Fresh dependency resolution in this check is not verifier qualification. Build, tests, loader and package smokes were repeated after adopting unscoped package names; external dependency lock entries remained unchanged.
- Live public catalogs: **44 NEAR and 7 Tinfoil** chat/tool models mapped at the time of testing. After per-model classification, **3 NEAR models** declare model-attestation support and are shown by default in SDK mode. Metadata remains provider claims, not deployment qualification.
- Live Tinfoil router evidence passed the pinned SDK verifier without inference. This establishes SDK acceptance only.
- The [opt-in live Pi harness](../scripts/live-pi.ts) loaded each compiled provider and used native secret login in an isolated owner-only store. A corrected Tinfoil credential enabled actual Pi CLI `gpt-oss-120b` completion/usage, stored-key precedence, Unicode tool execution/result follow-up, and reasoning/final-text checks across separate runs. The tested credentials were never logged.
- The experimental `PI_TINFOIL_ROUTE=direct` route passed the complete actual Pi suite in one run with `gemma4-31b`, including native login, stored-key precedence, tools/follow-up, reasoning and RPC cancellation. The [direct transport](../packages/tinfoil/src/direct.ts) pins a worker/artifact/measurement, binds the exact TLS socket before HTTP, and sends once. The [real TLS regression](../tests/pinned-tls.test.ts) confirms zero HTTP sends on a mismatched key. [Routing tests](../tests/direct-routing.test.ts) cover immutable routing and rejection of stale selections; [artifact tests](../tests/tinfoil-direct.test.ts) cover delivery-service substitution before inference.
- Cancellation uses a dedicated metadata pipe and a test-only response-consumption barrier after HTTP 200. A separate router cancellation retry passed with `gpt-oss-120b`; that route's intermittent SDK key-mismatch remains unresolved. No router retry or verification bypass was added. Local overload was observed, but is not established as the transport failure's cause.
- Separate [direct-worker qualification](direct-access.md) passed fresh v3 CPU verification with revocation/security policy and manufacturer-local GPU verification, plus wrong-nonce, changed-key/device and forged-GPU negatives. These stronger checks remain outside the registered SDK route. NEAR GLM direct research passed; Qwen remained `OutOfDate`. Neither result enables Approved workloads.
- The fresh locked install reported the existing NEAR dependency chain's low-severity [elliptic signing advisory](https://github.com/advisories/GHSA-848j-6mx2-7j84), with no patched release. Inspected DCAP code uses native Node verification; its browser fallback performs public-key verification, with no signing call found. The used path does not match the advisory's faulty-signature trigger; broader dependency qualification remains required.

## Outstanding security work

The user’s provider-independent trust objective is not fulfilled by SDK policy. Neither provider currently has an enabled Approved profile. A qualifying direct worker or enforced forwarding chain, independent artifact/measurement approval, hardware appraisal including revocation and security floors, complete key/runtime/GPU closure, live end-to-end validation and an independent verifier/transport review are required. NEAR additionally needs the serving-session and runtime/key-release contract established in the assessment. Whole-session protection needs a fail-closed physical-provider dispatch guard in Pi.

These requirements come from the [assessment/design](design.md), [Opus 5.5 design review](design-review.md) by Opus 5.5, and [review resolutions](review-resolution.md). That review covered the design; it is not an implementation security audit.

The WIP source is published in [ariofrio/pi-tee](https://github.com/ariofrio/pi-tee). The npm packages remain unpublished. No vendor PR, issue or message was created.

Written by Codex.
