# Changelog

## Unreleased

- Preserve reusable guarded request bodies for Tinfoil SDK key-rotation recovery; add a failing-then-passing provider regression without adding Pi retries or independent approval claims.
- Add opt-in, billable real Pi CLI/RPC validation with isolated native login, synthetic completion/tools/reasoning/cancellation checks and credential-safe diagnostics. Record current NEAR TCB-policy and Tinfoil credential failures without weakening verification policy.
- Adopt unscoped `pi-nearai`, `pi-tinfoil` and `pi-tee-core` package names; publish the WIP source and assessment under `ariofrio/pi-tee`.

- Hide NEAR models without declared serving-attestation support by default; add independent visibility settings and labeled show-all discovery without relaxing inference verification.
- Add separately installable NEAR AI and Tinfoil Pi provider extensions with shared policy and transport enforcement.
- Add native API-key login, public model catalogs, native stored refresh, provider-specific policy/report commands, and safe default blocking.
- Add SDK-policy transports; hold NEAR response bytes until model signature verification completes.
- Add payload/header/model guards, bounded buffering, cancellation and terminal retry suppression.
- Keep independently approved production profiles and session-wide protection gated; document their remaining requirements.

Written by Codex.
