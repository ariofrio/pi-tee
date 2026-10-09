# Security guarantees and limits

This file defines the protection boundary and contributor obligations. The [security model](docs/security-model.md) owns verified level meanings, the [policy reference](docs/reference/policy.md) owns syntax, and the [provider guide](docs/providers.md) discloses route behavior and credential recipients.

## Protection boundary

The extensions protect their own dispatches. They do not prevent another Pi provider, fallback, compaction, extension or tool from receiving conversation plaintext. The user's OS/runtime, Pi, enabled local code and shipped verifiers remain trusted. Whole-session protection requires a [Pi dispatch guard](docs/design/architecture.md#pi-integration-and-request-lifecycle).

The final guard fixes model, endpoint, authentication and allowed content after Pi hooks. Authentication precedes output/tool exposure. Direct routes bind the actual socket before credentials or ciphertext and reject reconnect/resend; the Tinfoil router is likewise bound to its freshly attested keys and sends once. Some gateways intentionally receive credentials/metadata over WebPKI while bodies remain encrypted to appraised keys. [Exact provider disclosures](docs/providers.md), [retry/response limits](docs/reference/support-limits.md).

Public-build positions trust named public publishers and workflows to authorize compatible releases automatically. A malicious authorized release may be accepted before detection; public evidence enables auditing, not guaranteed safety. Successful public dispatch reports `profile-established` and `profile-declared`, without an independently proven complete inventory; independent approval and whole-session protection remain unestablished. [Serving contract](docs/contracts/tinfoil-public-builds.md).

Catalog labels, prices and provider commitments do not establish verified levels. Output correctness, availability, truthful billing, traffic analysis, undocumented physical/side-channel protection and local-machine compromise are outside the guarantee. Ordinary logs omit credentials, prompts, completions and quote bodies; no background inference is added. Credentials are managed by Pi.

## Required closed inventory

Before enabling a production profile, document trusted parties/processes, authenticated artifacts/keys, update/freshness/revocation rules, and every plaintext or key recipient. Include local dependencies; CPU/GPU roots and channel policy; guest/runtime/model inputs; administrators/mutable configuration; key generation, release, migration and destruction; KMS, remote verifiers and bootstrap authorities. Delivery services count as trusted whenever they can authorize software, keys or recipients. [Trust declarations](docs/design/architecture.md#trust-declarations), [implemented Tinfoil inventory](docs/contracts/tinfoil-public-builds.md).

Verifier/transport changes require independent review and tests through actual cryptographic and dispatch boundaries before production enablement. Mocked success and package loading do not qualify a deployment. The lockfile fixes the tested dependency set; fresh tarballs can resolve different SDK dependencies and need separate qualification. Follow [CONTRIBUTING](CONTRIBUTING.md).

Written by Codex.

<a id="supported-guarantees"></a>

See the [security model](docs/security-model.md) and [provider guarantees](docs/providers.md).
