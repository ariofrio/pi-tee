# pi-tinfoil

Tinfoil provider extension for Pi 1.0.4 and Node 22.19 or later. Supports native API-key `/login tinfoil`, `TINFOIL_API_KEY`, live chat/tool model discovery, provider-declared thinking controls, Pi tools and usage, and EHBP encryption.

Build from the repository's locked workspace, then load `dist/extension.js` with `pi -e`. The shared `pi-tee-core` library is a dependency; it is not another extension. This package does not load NEAR's SDK.

Default `approved` policy hides models and blocks inference: no independently approved production profile is enabled. `PI_TINFOIL_POLICY=sdk` or `/tinfoil policy sdk` explicitly accepts the reported SDK-policy assumptions. `/tinfoil policy approved` restores blocking and aborts active requests. In-session choices are not persisted. `/tinfoil status`, `/tinfoil models`, and `/tinfoil models refresh` report status and refresh discovery. `PI_TEE_OFFLINE=1` disables startup discovery.

`PI_TINFOIL_ROUTE=direct` selects the experimental direct Gemma route at startup. In SDK policy it exposes only `gemma4-31b`, pins one worker, the exact `v0.0.25` artifact digest and launch measurement, and checks Sigstore provenance with verifier 1.2.2. Before transmitting either the API key or encrypted body, it checks the attested SPKI on the exact TLS 1.3 socket. It uses EHBP 0.3.3 directly, sends once, rejects rotation/error responses, and neither re-attests nor resends. Worker changes fail closed until the candidate is deliberately updated and reviewed. [Profile and transport](src/direct.ts), [socket binding](../core/src/pinned-tls.ts), [qualification evidence](../../docs/direct-access.md).

The direct route remains SDK policy. Its runtime JS verifier does not enforce fresh v3 evidence, AMD revocation or independent GPU appraisal. Stronger CPU/GPU research verification has passed separately; those checks are not yet integrated into the route. Pinned artifacts are not independent workload approval, and protected-session enforcement across other Pi providers is not implemented.

The default `PI_TINFOIL_ROUTE=router` uses `tinfoil` 1.2.2. It trusts the attested router and its backend/hardware release policy. The JS verifier supports AMD Genoa SEV-SNP and tagged-release Sigstore provenance, with no AMD certificate-revocation check. ATC/proxies can present an older authentic release; this route has no local rollback floor. The SDK can re-attest and resend on rotation without an independent approval point. GPU/channel assurance, egress and credential-dependent sidecars depend on accepted router/guest code. [SDK recovery](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts#L370).

Both routes use a fresh memory-only cache secret per request client. Caller URL/header/fetch overrides, remote media URLs, hosted tools and unclassified options are rejected. Pi provider retries are disabled and terminal failures are sanitized. Browser OAuth is not implemented.

On 2026-10-07, the direct route passed the complete actual Pi CLI/RPC suite with `gemma4-31b`: compiled loading, native secret login, stored-key precedence, completion/usage, Unicode tool execution/result follow-up, reasoning/final text and cancellation. Cancellation is exercised at a test-only response-consumption barrier after HTTP 200; it does not establish when the remote engine stops generation. The router also passed a separate actual Pi cancellation run with `gpt-oss-120b`; its intermittent SDK key-mismatch failure remains unresolved. [Live harness and validation record](../../README.md#validation).

Written by Codex.
