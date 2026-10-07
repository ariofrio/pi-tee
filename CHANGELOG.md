# Changelog

## Unreleased

- Hide NEAR models without declared serving-attestation support by default; add independent visibility settings and labeled show-all discovery without relaxing inference verification.
- Add separately installable NEAR AI and Tinfoil Pi provider extensions with shared policy and transport enforcement.
- Add native API-key login, public model catalogs, native stored refresh, provider-specific policy/report commands, and safe default blocking.
- Add SDK-policy transports; hold NEAR response bytes until model signature verification completes.
- Add payload/header/model guards, bounded buffering, cancellation and terminal retry suppression.
- Keep independently approved production profiles and session-wide protection gated; document their remaining requirements.
