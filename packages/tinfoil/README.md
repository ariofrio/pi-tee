# @ariofrio/pi-tinfoil

Tinfoil provider extension for Pi 1.0.4 and Node 22.19 or later. Supports native API-key `/login tinfoil`, `TINFOIL_API_KEY`, live chat/tool model discovery, provider-declared thinking controls, Pi tool handling and usage, SDK verification and EHBP encrypted transport.

Build from the repository's locked workspace, then load `dist/extension.js` with `pi -e`. The shared `@ariofrio/pi-tee-core` library is a dependency; it is not another extension. This package does not load NEAR's SDK.

Default `approved` policy hides models and blocks inference: no independently approved production profile is implemented. `PI_TINFOIL_POLICY=sdk` or `/tinfoil policy sdk` explicitly accepts SDK-policy authorities. `/tinfoil policy approved` restores blocking and aborts active requests. In-session choices are not persisted. `/tinfoil status`, `/tinfoil models`, and `/tinfoil models refresh` show the report and refresh discovery. `PI_TEE_OFFLINE=1` disables startup discovery.

SDK policy uses `tinfoil` 1.2.2 and its AMD Genoa SEV-SNP/Sigstore verifier. It trusts the attested router and its backend release policy, not independently approved model-worker software. The JS verifier performs local AMD chain validation but no certificate-revocation check. ATC/proxies can present an older authentic tagged release; no local rollback floor exists. The SDK can re-attest and resend on key rotation without independent approval before the resend. These behaviors are disclosed, not presented as Approved workloads.

GPU/channel assurance, runtime integrity, egress, and credential-dependent sidecars depend on the accepted guest/router code. The complete production closed trust inventory has not been established. An Approved transport must own bundle verification, exact code/hardware approval and rotation, and demonstrate direct-worker or enforced-router serving-path closure. [SDK automatic recovery](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts#L370).

A fresh memory-only cache secret is supplied to each request client. Caller URL/header/fetch overrides, remote media URLs, hosted tools and unclassified options are rejected. The wrapper disables Pi provider retries and normalizes terminal failures; the SDK's own rotation recovery still applies in SDK policy. Protection across other Pi providers is not implemented.

Browser OAuth and independently approved deployment profiles are not implemented. Current router evidence passed a live SDK verification smoke; authenticated live inference was not run because provider credentials were unavailable.
