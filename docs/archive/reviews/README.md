# Historical review scopes and commits

These seven reports retain every substantive finding, condition, correction and verdict. Their original authors and methods remain in the reports. Verdicts apply to the reviewed snapshots and proposed deltas, not to current `main`, later policy revisions or new providers. The [archive index](../README.md) and [evidence index](../../evidence/README.md) separate reviews from recorded validation.

## Original design

| Record | Scope / provenance | Verdict and follow-up |
| --- | --- | --- |
| [Design review](design-review.md) | 2026-10-06 design and pinned upstream sources; no inference, live attestation or rebuild. The report does not name an exact local review commit. [First committed document/design snapshot, df02e80](https://github.com/ariofrio/pi-tee/commit/df02e80) is provenance, not a newly inferred review target. | Ready for basic integration after medium fixes; Approved workloads and session protection remain gated. Original findings H1–H3, M1–M7 and L1 are preserved. |
| [Design resolutions](review-resolution.md) | Codex reconciliation dated 2026-10-06. [Public-build policy revision, eeb7a07](https://github.com/ariofrio/pi-tee/commit/eeb7a07) was subsequently selected and was outside the original review. | Records design changes, not implementation/test results or a second complete Opus review. Preserves the corrected AES-CBC integrity/rollback conclusion. |

The relative design links in these archived reports resolve to the [pre-cleanup document snapshot](https://github.com/ariofrio/pi-tee/blob/5f561f34e688f49739e3693dbc9a0c32362bcaba/docs/design.md). That evolving document is context, not evidence that the reviewer approved every later revision. The reports' exact upstream pins are unchanged.

## Public-build implementation and original setup

| Record | Reviewed commit / range | Original verdict / subsequent resolution |
| --- | --- | --- |
| [Public-build review](pi-tee-public-build-opus-review.md) | [205b1af](https://github.com/ariofrio/pi-tee/commit/205b1af); [718f385](https://github.com/ariofrio/pi-tee/commit/718f385) inspected only for F1 | No high-severity bug; predicate/subject binding gap, frozen GPU policy and remaining finite production gates. F1–F8 subsequently resolved by the session review; F9 remained informational. |
| [Combined session review](pi-tee-public-session-opus-review.md) | [205b1af..da48839](https://github.com/ariofrio/pi-tee/compare/205b1af...da48839), including 718f385 | No concrete bug in the combined verifier/session/transport; F1–F8 resolved. Setup image and activation still required separate review; local macOS ARM64/Docker scope. |
| [Pinned local-setup review](pi-tee-local-setup-opus-review.md) | [da48839..c91d3f8](https://github.com/ariofrio/pi-tee/compare/da48839...c91d3f8) | No setup bug; independently checked pinned image contents; D1–D6 resolved. Separate routing/flag review and exact Docker build configuration still required. |
| [Routing/enablement review](pi-tee-enablement-opus-review.md) | [c91d3f8..9840501](https://github.com/ariofrio/pi-tee/compare/c91d3f8...9840501) and the proposed flag flip, tested in a throwaway copy | Flip safe to apply with test/docs adjustments in the same change and the stated live-validation conditions. This is the original Gemma/native setup scope, not the later WASM or multi-model sign-off. |

## Multi-model, SNP, TLS and cache sequence

All stages below remain in the [complete multi-model/SNP/TLS report](pi-tee-multimodel-snp-tls-opus-review.md), including original findings later fixed. Locally proposed/rebased commit IDs are preserved exactly as recorded; the cited report is the fallback when an old unpushed commit is unavailable from the remote.

| Report section | Reviewed scope / commits | Verdict and conditions |
| --- | --- | --- |
| [Initial review](pi-tee-multimodel-snp-tls-opus-review.md#verdict-enable-after-fixes) | [df31083..520f0ae](https://github.com/ariofrio/pi-tee/compare/df31083...520f0ae), [246891b](https://github.com/ariofrio/pi-tee/commit/246891b), scoped WASM migration [dd518cc](https://github.com/ariofrio/pi-tee/commit/dd518cc) | Enable after fixes: High stale Genoa floors, omitted plaintext sidecar, malformed-header crash; preserve the other transport/topology findings and conditions. |
| [Re-review](pi-tee-multimodel-snp-tls-opus-review.md#re-review-at-ad71a91-fixes-0e3add3-ea382e6-8b33709) | [246891b..ad71a91](https://github.com/ariofrio/pi-tee/compare/246891b...ad71a91); fixes [8b33709](https://github.com/ariofrio/pi-tee/commit/8b33709), [0e3add3](https://github.com/ariofrio/pi-tee/commit/0e3add3), [ea382e6](https://github.com/ariofrio/pi-tee/commit/ea382e6) | Enable: all three original conditions met. Resolves floors, production policy, engine image, TLS and probing findings; retains the Low/Info residuals, including partial Bun backpressure, addressed by later sections. |
| [Enablement review](pi-tee-multimodel-snp-tls-opus-review.md#enablement-review-at-94b43a7) | Proposed local `94b43a7`, [ecc5cd0](https://github.com/ariofrio/pi-tee/commit/ecc5cd0), [6ea1329](https://github.com/ariofrio/pi-tee/commit/6ea1329) | Enable with review A sign-off on NVIDIA/WASI/bridge `37eba73..13b116f` and exact-commit production suites for all three models under Node and Bun before pushing. |
| [Cache/rebase delta](pi-tee-multimodel-snp-tls-opus-review.md#delta-review-d0bd843-and-the-rebased-enablement-commit) | [d0bd843](https://github.com/ariofrio/pi-tee/commit/d0bd843); local rebased `dbbec6f` and `e6cb1b7` | Enable; same review/live conditions. `e6cb1b7` includes the report copy. Low private-cache hardening item and original whole-cache deletion behavior remain documented here. |
| [Post-merge delta](pi-tee-multimodel-snp-tls-opus-review.md#post-merge-delta-7b8ee9f-and-5fbe387) | [7b8ee9f](https://github.com/ariofrio/pi-tee/commit/7b8ee9f), [5fbe387](https://github.com/ariofrio/pi-tee/commit/5fbe387), after enablement merge [37e3b5e](https://github.com/ariofrio/pi-tee/commit/37e3b5e) | OK; neither widens acceptance. Resolves the Low hardening item and verifies independent per-entry persistence; keeps ancestor-directory and abort/refetch informational limits. |

## Current obligations and reachability

- [CONTRIBUTING](../../../CONTRIBUTING.md) retains native-seam testing, required checks, independent review and all hardware/serving/runtime/artifact gates before enabling production profiles. Archiving a report does not satisfy a new review gate.
- [SECURITY](../../../SECURITY.md), the [security model](../../security-model.md) and [Tinfoil contract](../../tinfoil-public-profile.md) retain active protection boundaries, authorities and limitations. Whole-Pi-session protection and NEAR public-build qualification are not established by these historical enablement verdicts.
- Native Docker/OrbStack prerequisites remain as historical scope in the setup reports; current packaged verifier build requirements are in [the tool procedure](../../../tools/nvidia-verifier/README.md). Later verifier/platform validation is linked from [the client record](../../evidence/client/implementation-validation.md#security-model-validation), not retroactively attributed to these five reviews.
- Each old report path retains its original headings as onward links. Git retains original locations and text; use `git log --follow --find-copies=20% --find-copies-harder -- <new-path>` to trace moves when a compatibility page occupies the old path. Retain stubs until inbound citations have been migrated.
