# Evidence index

These are dated observations and source investigations. A passing run qualifies its stated commit, dependencies, route, runtime and sampled workers; it is not a promise about today's fleet. The [security model](../security-model.md) defines policy and the [Tinfoil serving contract](../contracts/tinfoil-public-builds.md) defines its accepted authorities. [Procedures](../procedures/README.md) describe how to check a new revision; [archived reviews](../archive/README.md) retain earlier verdicts.

## Client validation

| Record | Observation date / scope | Applicability |
| --- | --- | --- |
| [Security-model and earlier client validation](client/implementation-validation.md) | 2026-10-07–09; locked Node 24, Bun and Pi 1.0.4, direct and gateway/router suites | The security-model section records credentialed NEAR GLM suites on Node and Bun, six default Tinfoil direct suites, and the Bun router loading failure. The 126-test count and two-provider inventory precede Chutes. Earlier policies and setup remain historical. |
| [Portable verification](client/portable-verification.md) | 2026-10-07–09; WASM/source boundaries, six desktop CI targets and Android emulator | The earlier NEAR Bun “not yet run” statement is superseded by the security-model run above. Android has credential-free appraisal, not a live Pi suite. Architecture descriptions reflect the preserved source snapshot. |

| [Pre-restructure design/investigation snapshot](client/2026-10-09-design-assessment.md) | Preserved from main fa5e154, 2026-10-09 | Source investigations and old availability conclusions retain their original scope; current architecture/adapter behavior lives separately. |

## Tinfoil

| Record / receipts | Observation date / scope | Limits |
| --- | --- | --- |
| [Workload investigation](tinfoil/workload.md), [measurement metadata](tinfoil/tinfoil-workload-evidence.json), [build inputs](tinfoil/tinfoil-build-inputs.json) | 2026-10-07; Gemma deployment, guest build, RTMR calculation, Nix input inventory and OCI trace | Public-publisher attribution, not independent image rebuild or complete runtime inventory. Original native/OrbStack setup is historical. |
| [Public-build metadata](tinfoil/public-build-evidence.json), [probe and checks](../../tools/tinfoil-public-build/README.md) | 2026-10-07; CPU/release/guest/OCI chain | Sanitized digests/claims; no raw quote or key. The record's `commit` is the workload publisher commit, not the client test commit. GPU and inference are separately qualified. |
| [Public-profile validation metadata](tinfoil/public-profile-validation.json) | 2026-10-07; original Gemma production-enablement/setup scope | Retains native-helper/container facts and verdicts; it does not describe present WASM setup or independently qualify later policy changes. |
| [GPU investigation](tinfoil/gpu-runtime.md) | 2026-10-07 sample and subsequent tests; Hopper SPT, Blackwell MPT, signed-field negatives and driver source | Source traces and manufacturer contracts; no physical-reset experiment, complete CUDA trace or live signed PPCIe/devtools negative. |
| [Billing-gateway validation](tinfoil/gateway-validation.md#validation) | 2026-10-09; Node and Bun Pi suites for DeepSeek/GLM, relay appraisal and terminal 412 | Cancellation proves local acknowledgement; frame-boundary truncation and sealed-request replay remain disclosed limits. The active contract is in the provider guide; this record preserves the run. |

| [Helper source and verification narrative](tinfoil/helper-investigation.md) | Preserved from main fa5e154; original run dates retained | CPU/guest/OCI/runtime stages, bounds and cache investigations; standalone success is not live serving qualification. |

## Other providers

| Record / receipts | Observation date / scope | Limits |
| --- | --- | --- |
| [Privatemode validation/source investigation](providers/privatemode-validation.md) | 2026-10-09; SDK 1.58.0/Contrast 1.24.1; Node 26.10/Bun 1.3.13 Pi suites for three models and authenticated zero-inference negatives | A2/H3/G3/X3; one GLM synthetic-marker run retried; no raw/private quotes committed; current manifest contract is in the provider guide. |
| [Chutes validation](../chutes-validation.md), [Node Pi results](../validation/chutes/node-live-pi.txt), [Bun Pi results](../validation/chutes/bun-live-pi.txt), [Node evidence sample](../validation/chutes/node-attestation.json), [Bun evidence sample](../validation/chutes/bun-attestation.json) | 2026-10-09; merged adapter at [605b1ed](https://github.com/ariofrio/pi-tee/commit/605b1ed51ed65750eb51a3d8c7af34e1c3c1ea7e), one live Pi model and 12-model evidence samples per runtime | Per-request instance appraisal; rejected rows remain rejected. Neither samples nor source establish permanent fleet ratings. Raw private evidence is not committed. |
| [NEAR direct model discovery and validation](../near-direct-discovery.md#live-validation-2026-10-09) | 2026-10-09; merged discovery at [c4df58e](https://github.com/ariofrio/pi-tee/commit/c4df58ec5d74584575973a007980158c101cdac7), three-model evidence sample and GLM/Qwen3.6 Pi suites under Node and Bun | GLM H1 and Qwen H2 are sampled endpoint ratings; all remain A3/G3/X3. Qwen3.8 is evidence-only. Discovery never authorizes inference or establishes fleet-wide guarantees. |
| [NEAR commitment observations](nearai/commitments.md) | Preserved 2026-10-09 source/terms paragraph; exact source/terms pins were not supplied | Not newly requalified, and incomplete citation provenance limits reproduction; no admission effect. |
| [NEAR direct investigation](nearai/direct-access.md#near-direct-route-and-evidence), [direct receipts](nearai/direct-access-evidence.json), [gateway receipts](nearai/near-gateway-evidence.json), [runtime/key investigation](nearai/runtime-key-custody.md) | Dates and pinned revisions stated in the records | The source investigations and earlier receipts have narrower scope than the discovery qualification above; use that record for the sampled multi-model results and the security model for current policy. |
| [Provider-rating verification](../provider-ratings-verification.md), [ecosystem survey](../provider-survey.md) | 2026-10-09 investigation; public sources and stated private receipts | Prospective ecosystem evidence is distinct from installed adapter qualification. Unresolved/contradictory cells require reconciliation; the survey is not an implementation reference. |

## Recording and maintaining observations

- New records name UTC observation time, client commit and dependency lock, upstream pins, provider/model/route/runtime, sampled population, authenticated versus decoded-only fields, positive/negative outcomes, inference/billing scope, fixture/skips and receipt links.
- Preserve old outcomes, failures and verdicts. A new run gets a separate record; update this index to say which earlier qualification it supersedes and why. Never infer a run commit from a document's last-edit commit.
- Revisit applicability when adapters, policy, trust authorities, verifier pins, CPU/GPU floors, SDK/Pi dependencies or release behavior change. Until rerun, describe the old qualification as historical or unqualified for the changed scope.
- Keep credentials, private keys, raw provider evidence and transcripts private. Public records contain sanitized metadata/digests. A private receipt needs an identifier and an access description; absence of the receipt limits independent reproduction.
- Documentation age and per-request evidence freshness are separate: a seven-day witness rule does not make a week-old observation a live deployment guarantee.
