# Opus 5.5 review: policy routing at `9840501` and the proposed enablement flip

**Scope**
- Fixed commit [`9840501`](https://github.com/ariofrio/pi-tee/commit/9840501d3f6f9d8cb8d07bf0b6725d952878fa82), the range `c91d3f8..9840501`.
- The exact proposed change in [public-policy.ts#L36-L38](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/packages/tinfoil/src/public-policy.ts#L36-L38): `PUBLIC_BUILD_PROFILE_ENABLED = false` → `true`, plus a comment saying the macOS ARM64 profile and local setup have been reviewed.

**What I ran**
- Reviewed and tested a `git archive` snapshot.
- Tested the flip only in a throwaway copy (`work/flip-9840501`), never in the repository.
- No inference, secrets or external contact. The only local command outside the snapshot was the appraisal's own read-only `docker context inspect`.

Earlier reviews: [public-build](pi-tee-public-build-opus-review.md), [session](pi-tee-public-session-opus-review.md), [local setup](pi-tee-local-setup-opus-review.md).

## Verdict

- **Code:** no security bug in the routing delta or the one-line flip. The flip is safe to apply.
- **Required in the same change:** the test adjustments and the documentation updates listed below. Without them the suite fails, and the repository would still state that public-build inference is blocked.

## Routing delta (`9840501`)

Behavior with the flag set to `true` ([index.ts#L23-L56](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/packages/tinfoil/src/index.ts#L23-L56)):

| Policy | Route | Result |
| --- | --- | --- |
| `public-builds` (default) | `auto` (default) or `direct-public` | Owned Intel profile only. Picker filtered to `publicProfile.modelIds` ([provider.ts `selectableCatalog`](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/packages/core/src/provider.ts)). `openSdkTransport` is never called in this mode. |
| `public-builds` | `router`, `direct` or `direct-intel` | No profile, so `TEE_PUBLIC_BUILD_DEPLOYMENT_UNAVAILABLE` before any SDK opener runs. Tested at [tinfoil-intel.test.ts](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/tests/tinfoil-intel.test.ts). |
| `sdk` | `auto` | Stock SDK router with the full catalog and router assumptions. This is explicit user opt-in, unchanged from the old `router` default. |
| `approved` | any | Empty picker; `TEE_APPROVED_DEPLOYMENT_UNAVAILABLE`. |

- **No environment override.** `PI_TINFOIL_ROUTE` and `PI_TINFOIL_POLICY` select among the reviewed paths. Nothing turns a public dispatch into an SDK dispatch or enables the profile outside this constant.
- **Assumptions follow policy.** Public-profile assumptions are copied at construction and chosen by policy in `updateReport`, which `setPolicy` now calls. This is display only; admission and session checks are unchanged from `da48839`.
- **Assumption text is accurate.** The eight public assumptions ([intel.ts#L16-L25](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/packages/tinfoil/src/intel.ts#L16-L25)) match [tinfoil-public-profile.md](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/docs/tinfoil-public-profile.md). They claim neither manufacturer-only trust nor whole-session protection.
- **The `--public-builds` harness drives the real extension.** It refuses to combine with candidate registration ([live-pi.ts](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/scripts/live-pi.ts)), and [extension.ts](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/packages/tinfoil/src/extension.ts) calls `createTinfoilProvider()` with defaults, so `auto` and `public-builds` are what get exercised.
- **L1 and L2 from the local-setup review are resolved.** The docs scope support to OrbStack 29.4.0 / buildx 0.33.0 with the containerd store, and the setup test uses `--no-deprecation`.

## Evidence

**Fixed commit:** isolated build and typecheck pass. 62 tests: 59 pass, 3 skipped (private fixtures), 0 fail. Run on Node 26.10.0, since Node 24 is not available here.

**Exact flip, in a throwaway copy:**
- Only the expected test fails: "the dynamic-build candidate rejects an untrusted helper…". It asserts that the picker is empty under public policy, which flips by design.
- An offline probe of the default factory (stubbed catalog, `globalThis.fetch` blocked, untrusted helper bytes, injected SDK opener) showed:
  - public picker `['gemma4-31b']`, with public assumptions reported;
  - the dispatch with `maxRetries: 10` fails as `TEE_VERIFIER_ARTIFACT_REJECTED`, with SDK opener calls 0, network calls 0 and `publicBuildVerification: not-established`;
  - `approved` gives an empty picker;
  - `sdk` gives the full catalog and router assumptions.

This confirms the activation regression the parent plans to add.

## Conditions that must land with the flip (same commit)

1. **Tests**
   - Replace the candidate test's empty-picker assertion with the planned production checks:
     - picker contains only `gemma4-31b`;
     - an invalid helper is rejected before inference with `maxRetries: 10`;
     - the SDK opener is never called;
     - `approved` is empty;
     - `sdk` restores the catalog and assumptions.
   - Run the full suite with the private fixtures.
2. **Documentation that becomes false when the flag is `true`.** Update each statement to say the profile is available only for the supported macOS ARM64 / OrbStack setup and the declared serving contract, with NEAR and Approved still gated:
   - [SECURITY.md#L3](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/SECURITY.md#L3): "No complete inference profile is enabled yet" and "Built-in production admission is still gated pending reviewed local setup".
   - [design.md#L15](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/docs/design.md#L15) (table: "Blocked until a full serving profile passes the remaining gates") and [#L96](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/docs/design.md#L96) ("Production remains gated…").
   - [packages/tinfoil/README.md#L17](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/packages/tinfoil/README.md#L17) ("Public-build and Approved inference remain blocked") and [#L28](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/packages/tinfoil/README.md#L28) ("Production admission remains gated…").
   - [packages/core/README.md#L13](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/packages/core/README.md#L13) ("the built-in production profiles are still gated").
   - [tinfoil-public-profile.md#L3](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/docs/tinfoil-public-profile.md#L3) ("Production admission remains disabled until…").
   - [tinfoil-gpu-runtime.md#L3](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/docs/tinfoil-gpu-runtime.md#L3) ("production admission remains gated").
   - [tinfoil-workload.md#L33](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/docs/tinfoil-workload.md#L33): the "gated" sentence.
   - [CHANGELOG.md#L5](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/CHANGELOG.md#L5) ("still gated for final wiring review"). Add a new entry for the activation instead of rewriting history.
3. **Flag comment.** Keep the non-configurability statement and name the reviewed scope instead of claiming general verification. Suggested wording:
   ```ts
   // Enabled after the Opus 5.5 reviews of the public-build chain, owned session
   // (da48839), local verifier setup (c91d3f8) and policy routing (9840501).
   // Supported only on macOS ARM64 with the documented local setup; other
   // environments fail closed. Deliberately not configurable by environment.
   export const PUBLIC_BUILD_PROFILE_ENABLED = true;
   ```
4. **Live validation after the flip.** Run the parent's planned `--public-builds` suite through the actual compiled extension, plus the independent live-delta cancellation. These observations are still to be done; this review does not cover them.

## Non-blocking notes

- **Unsupported platforms.** On machines other than macOS ARM64, or without the configured setup, the public picker still lists `gemma4-31b` but dispatch fails with `TEE_RUNTIME_UNSUPPORTED` before any network contact. This fails closed. Optionally hide or label the model there to avoid confusion.
- **Behavior change for existing users.** Users relying on the old default (router route, public policy) were previously blocked. They now get the owned Intel route, or a clear failure. Users who want the router must choose `sdk` policy explicitly. Call this out in the activation changelog entry.
- **Unrelated stale sentences.** [CHANGELOG.md#L37](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/CHANGELOG.md#L37) and [review-resolution.md#L5](https://github.com/ariofrio/pi-tee/blob/9840501d3f6f9d8cb8d07bf0b6725d952878fa82/docs/review-resolution.md#L5) are historical or Approved-specific. Leave them.

NEAR and Approved remain gated. Whole-session protection remains unestablished.

Written by Claude Opus 5.5.
