# Security guarantees and limits

This file defines what the extensions protect and what contributors must preserve. Installation belongs in the [README](README.md); provider evidence and implementation details belong in the linked assessments.

## Supported guarantees

The default `public-builds,egress=metadata` requires Tinfoil public release, fresh current CPU evidence, fully protected and covered GPUs, and metadata-only handling. Its named public publishers and build workflows authorize compatible updates automatically. H2 Genoa workers require an explicit host-trusting policy; Intel `OutOfDate` Tinfoil direct workers remain unavailable under every policy.

NEAR and the Tinfoil router require a position that admits provider-controlled software and host trust. NEAR's fresh CPU evidence receives H1 only after local firmware and collateral floors pass; its incomplete GPU coverage is G3 regardless of successful optional local diagnostics. No NEAR route contacts NRAS. The router is A3/H3/G3/X3, including hidden plaintext recipients. [Security positions, thresholds and migration](docs/security-model.md).

Every candidate is admitted against the same policy; failures never relax it. Selection compares code, host, GPU and egress. `sdk` and `approved`, and provider-specific policy/route environment variables, are removed with migration errors. Stronger build reproduction and pinned/window review are not yet supported.

Successful public dispatches report `publicBuildVerification: profile-established` and `closedTrustSet: profile-declared`. These mean the named profile's checks passed under its declared trust contract. They do not certify an independently proven complete software inventory. `independentApproval` and `protectedSession` remain `not-established`.

## Protection boundary

The extensions protect their own dispatches. They do not prevent another Pi provider, fallback, compaction, extension or tool from receiving conversation plaintext. The user's OS, runtime, enabled local code and the shipped verifier modules remain trusted. Whole-session protection needs a [Pi dispatch guard](docs/design.md#pi-integration-and-request-lifecycle).

Direct routes check the attested key on the actual TLS socket before sending credentials or ciphertext, then reject reconnect/resend. The SDK router retains its disclosed rotation retry. NEAR exposes completion and tool output only after response-signature verification; Tinfoil streams authenticated encrypted responses. Credentials are managed by Pi. Ordinary logs exclude credentials, prompts, completions and quote bodies; no background inference is added.

Catalog metadata, prices and TEE labels are provider claims, not verification. Output correctness, availability, truthful billing, traffic analysis, undocumented physical/side-channel protection and local-machine compromise are outside the guarantee.

The Tinfoil billing gateway receives API credentials, model and headers over normal WebPKI TLS to an unattested host. The client freshly appraises the worker through its nonce relay and encrypts bodies to that worker's own key. Direct is preferred; the gateway is tried only when no direct worker qualifies. A 412 is terminal, with no automatic resend. This metadata recipient is disclosed in `/tinfoil status` and is separate from the route's axis levels. [Gateway contract](docs/tinfoil-gateway.md).

## Required closed inventory

Before enabling a production profile, document its trusted parties and processes, authenticated artifacts and keys, update/freshness/revocation rules, and every plaintext or key recipient. Include local dependencies; CPU/GPU roots and channel policy; all guest/runtime/model inputs; administrators and mutable configuration; key generation, release, migration and destruction; and any KMS, remote verifier or key-bootstrap authority. Delivery services count as trusted whenever they can authorize software, keys or recipients. See the [design](docs/design.md#trust-declarations) and [implemented Tinfoil inventory](docs/tinfoil-public-profile.md).

Changes to verifier or transport behavior require independent review and tests through actual cryptographic and dispatch boundaries before production enablement. Mocked success and package-load tests do not qualify a deployment. The repository lockfile fixes the tested dependency set; fresh tarball installs may resolve different SDK dependencies and need separate qualification. Follow [CONTRIBUTING.md](CONTRIBUTING.md).

Written by Codex.
