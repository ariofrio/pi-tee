# Security guarantees and limits

This file defines what the extensions protect and what contributors must preserve. Installation belongs in the [README](README.md); provider evidence and implementation details belong in the linked assessments.

## Supported guarantees

The default `public-builds` policy currently admits Tinfoil Gemma on the tested macOS ARM64/OrbStack setup. Each dispatch requires fresh hardware verification, authenticated public build artifacts and the [declared serving contract](docs/tinfoil-public-profile.md). Named software publishers and build workflows may authorize compatible updates automatically. They include provider-operated authorities: this policy does not trust only hardware manufacturers or require independent review of every release.

NEAR's experimental SDK route is implemented and tested. Its public-build profile is not implemented; the [NEAR assessment](docs/nearai-status.md) separates unfinished client checks, missing deployment evidence and backend protocol requirements. `sdk` policy explicitly accepts the selected route's weaker assumptions. `approved` is reserved for independent frozen-workload approval and currently admits no models. Verification failures never fall back to a weaker policy.

Successful public dispatches report `publicBuildVerification: profile-established` and `closedTrustSet: profile-declared`. These mean the named profile's checks passed under its declared trust contract. They do not certify an independently proven complete software inventory. `independentApproval` and `protectedSession` remain `not-established`.

## Protection boundary

The extensions protect their own dispatches. They do not prevent another Pi provider, fallback, compaction, extension or tool from receiving conversation plaintext. The user's OS, runtime, enabled local code and verifier installation remain trusted. Whole-session protection needs a [Pi dispatch guard](docs/design.md#pi-integration-and-request-lifecycle).

Direct routes check the attested key on the actual TLS socket before sending credentials or ciphertext, then reject reconnect/resend. The SDK router retains its disclosed rotation retry. NEAR exposes completion and tool output only after response-signature verification; Tinfoil streams authenticated encrypted responses. Credentials are managed by Pi. Ordinary logs exclude credentials, prompts, completions and quote bodies; no background inference is added.

Catalog metadata, prices and TEE labels are provider claims, not verification. Output correctness, availability, truthful billing, traffic analysis, undocumented physical/side-channel protection and local-machine compromise are outside the guarantee.

## Required closed inventory

Before enabling a production profile, document its trusted parties and processes, authenticated artifacts and keys, update/freshness/revocation rules, and every plaintext or key recipient. Include local dependencies; CPU/GPU roots and channel policy; all guest/runtime/model inputs; administrators and mutable configuration; key generation, release, migration and destruction; and any KMS, remote verifier or key-bootstrap authority. Delivery services count as trusted whenever they can authorize software, keys or recipients. See the [design](docs/design.md#trust-declarations) and [implemented Tinfoil inventory](docs/tinfoil-public-profile.md).

Changes to verifier or transport behavior require independent review and tests through actual cryptographic and dispatch boundaries before production enablement. Mocked success and package-load tests do not qualify a deployment. The repository lockfile fixes the tested dependency set; fresh tarball installs may resolve different SDK dependencies and need separate qualification. Follow [CONTRIBUTING.md](CONTRIBUTING.md).

Written by Codex.
