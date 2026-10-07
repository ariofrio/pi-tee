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

Both extensions use Pi's native API-key login and stored model-refresh APIs. Commands select policy, report status, show discovery and force refresh. Provider requests reuse Pi's OpenAI conversion, tools, reasoning and usage. The final transport fixes the endpoint/model/auth headers and rejects hosted tools, remote media and unclassified payload fields. Errors use fixed terminal codes and Pi provider retries are disabled. Tinfoil's internal rotation resend is retained and disclosed only in SDK mode.

NEAR discovery additionally checks public per-model capability metadata in [`loadNearCatalog()`](../packages/nearai/src/discovery.ts). Its default TEE-only filter hides non-TEE and unknown models, using the SDK's `providerType: "vllm"` and `attestationSupported: true` selection rule with an exact model-ID match. This is an unverified provider claim. `PI_NEARAI_MODEL_VISIBILITY=all` or `/nearai models all` displays labeled blocked discoveries; `/nearai models tee` restores the filter. Showing models does not relax inference gates, and Approved policy still hides every picker model. [Visibility, cache and pre-send tests](../tests/near-visibility.test.ts) exercise this distinction.

NEAR requires Node 24 with the relevant TLS APIs, attested gateway TLS, OHTTP, model encryption, UpToDate CPU status, GPU evidence and a model-serving response signature. `authenticateResponse()` releases no body bytes before verification. Decrypted response bodies are capped at 8 MiB and pinned gateway network bodies at 32 MiB before SDK retention; these are body limits, not a total process-memory budget. Pi/Bun compatibility is not assumed.

## Validation

- Locked checkout: Node 24.21.0, Pi AI/coding-agent 1.0.4, NEAR SDK 0.1.0 and Tinfoil 1.2.2. Pi and SDK versions are exact pins. The root lockfile freezes transitive artifacts; fresh tarball installs may resolve a different dependency set.
- `npm run check`: build, package/test/script type checks and **29 passing tests**. [Tests](../tests/provider.test.ts) use the real Pi OpenAI adapter with controlled external transport responses, including payload overrides, hosted tools, retry classification, Unicode tool arguments, forged tool responses and cancellation. The rotation regression failed with a consumed `Request` and passes with reusable guarded bytes. This retains the SDK's disclosed resend policy rather than adding a Pi retry. [Refresh tests](../tests/refresh.test.ts) cover freshness, forced refresh, offline restoration, failure retention and generation-checked publications. [Response tests](../tests/response.test.ts) cover verification barriers, truncation/mixed identity, size limits and cancellation.
- `npm run smoke`: both compiled entries load through Pi's real resource loader; native API-key login works using synthetic credentials in an isolated store.
- `npm run smoke:packages`: both tarballs install and load independently outside the repository's module-resolution path, accept native login, and have no resolvable copy of the other provider's SDK. Required compiled entries, type declarations, README and license are included. Fresh dependency resolution in this check is not verifier qualification. Build, tests, loader and package smokes were repeated after adopting unscoped package names; external dependency lock entries remained unchanged.
- Live public catalogs: **44 NEAR and 7 Tinfoil** chat/tool models mapped at the time of testing. After per-model classification, **3 NEAR models** declare model-attestation support and are shown by default in SDK mode. Metadata remains provider claims, not deployment qualification.
- Live Tinfoil router evidence passed the pinned SDK verifier without inference. This establishes SDK acceptance only.
- The [opt-in live Pi harness](../scripts/live-pi.ts) loaded each compiled provider and used native secret login in an isolated owner-only store. NEAR inference was rejected during gateway verification with `policy.tcb_status_not_allowed`: observed TDX TCB status `OutOfDate`, required `UpToDate` ([policy configuration](../packages/nearai/src/index.ts)). Tinfoil inference returned HTTP 401 `invalid_api_key`; the official SDK's default attested route independently returned the same status/code. The tested credentials were never logged. Successful live completion, tools, reasoning and cancellation remain unvalidated; the harness stops on terminal inference failures.

Package-load checks establish installability, registration, login and SDK separation; they do not qualify newly resolved verifier dependencies or deployed workloads. See the [run instructions](../README.md#run-the-local-build).

## Outstanding security work

The user’s provider-independent trust objective is not fulfilled by SDK policy. Neither provider currently has an enabled Approved profile. A qualifying direct worker or enforced forwarding chain, independent artifact/measurement approval, hardware appraisal including revocation and security floors, complete key/runtime/GPU closure, live end-to-end validation and an independent verifier/transport review are required. NEAR additionally needs the serving-session and runtime/key-release contract established in the assessment. Whole-session protection needs a fail-closed physical-provider dispatch guard in Pi.

These requirements come from the [assessment/design](design.md), [Opus 5.5 design review](design-review.md) by Opus 5.5, and [review resolutions](review-resolution.md). That review covered the design; it is not an implementation security audit.

The WIP source is published in [ariofrio/pi-tee](https://github.com/ariofrio/pi-tee). The npm packages remain unpublished. No vendor PR, issue or message was created.

Written by Codex.
