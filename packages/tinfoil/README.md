# pi-tinfoil

Tinfoil provider extension for Pi 1.0.4 and Node 22.19 or later. Supports native API-key `/login tinfoil`, `TINFOIL_API_KEY`, live chat/tool model discovery, provider-declared thinking controls, Pi tool handling and usage, SDK verification and EHBP encrypted transport.

Build from the repository's locked workspace, then load `dist/extension.js` with `pi -e`. The shared `pi-tee-core` library is a dependency; it is not another extension. This package does not load NEAR's SDK.

Default `approved` policy hides models and blocks inference: no independently approved production profile is implemented. `PI_TINFOIL_POLICY=sdk` or `/tinfoil policy sdk` explicitly accepts SDK-policy authorities. `/tinfoil policy approved` restores blocking and aborts active requests. In-session choices are not persisted. `/tinfoil status`, `/tinfoil models`, and `/tinfoil models refresh` show the report and refresh discovery. `PI_TEE_OFFLINE=1` disables startup discovery.

SDK policy uses `tinfoil` 1.2.2 and its AMD Genoa SEV-SNP/Sigstore verifier. It trusts the attested router and its backend release policy, not independently approved model-worker software. The JS verifier performs local AMD chain validation but no certificate-revocation check. ATC/proxies can present an older authentic tagged release; no local rollback floor exists. The SDK can re-attest and resend on key rotation without independent approval before the resend. These behaviors are disclosed, not presented as Approved workloads.

GPU/channel assurance, runtime integrity, egress, and credential-dependent sidecars depend on the accepted guest/router code. The complete production closed trust inventory has not been established. An Approved transport must own bundle verification, exact code/hardware approval and rotation, and demonstrate direct-worker or enforced-router serving-path closure. [SDK automatic recovery](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts#L370).

A fresh memory-only cache secret is supplied to each request client. Caller URL/header/fetch overrides, remote media URLs, hosted tools and unclassified options are rejected. The request guard hands off reusable validated body bytes so the SDK can reconstruct its request on rotation without a consumed-body error. The wrapper disables Pi provider retries and normalizes terminal failures; the SDK's own rotation recovery still applies in SDK policy. Protection across other Pi providers is not implemented.

Browser OAuth and independently approved deployment profiles are not implemented. Router evidence passed a live SDK verification smoke. On 2026-10-07, a corrected credential enabled actual Pi CLI completion/usage, stored-key precedence, Unicode tool execution/result follow-up, and reasoning/final-text checks with `gpt-oss-120b` across separate runs. Text reasoning replay is supported and structured reasoning is rejected before transmission. Cancellation and a complete live-suite pass remain unvalidated: later runs encountered intermittent transport failures, including a key-configuration mismatch after the SDK's own re-attestation resend. No extra retry or verification bypass was added. See the [live harness and validation record](../../README.md#validation).

Separate [direct-worker research](../../docs/direct-access.md) verified a reachable Gemma SEV worker and completed EHBP inference directly with the existing user key. Its exact authenticated deployment artifact is recorded for review. This bypasses the decrypting router in the research probe; the extension still uses its existing route, and no independently approved profile is enabled.

Written by Codex.
