# Opus 5.5 review: public-build session, verifier and transport at `da48839`

Scope: fixed commit [`da48839`](https://github.com/ariofrio/pi-tee/commit/da48839) (`205b1af..da48839`, including [`718f385`](https://github.com/ariofrio/pi-tee/commit/718f3852b766d41b42327152cceedbe84458a35a)), reviewed from a `git archive` snapshot. Prior review: [pi-tee-public-build-opus-review.md](pi-tee-public-build-opus-review.md). The parent's later local-setup work (verifier image, installer) is **not** reviewed here.

Trust model applied: named, provider-operated public publishers, workflows and hosted build processes authorize software and measurements. Manufacturer contracts (Intel, NVIDIA) and the accepted publisher's software contracts supply runtime, key, channel and reset semantics. The following are not required: independent rebuilds, per-release source review, model-origin tracing, physical reset or non-SPT experiments, and a second live deployment.

Links of the form `B/…` point to `https://github.com/ariofrio/pi-tee/blob/da48839/…`.

## Verdict

- **No concrete security bug found** in the combined verifier, owned session or transport at `da48839`.
- All prior findings F1–F8 are resolved; F9 is informational and unchanged.
- The remaining items are documentation-accuracy and availability-hardening points. None of them blocks the security claim.
- **Limited macOS ARM64 scope.** The claimed security needs nothing beyond:
  1. honest support limits;
  2. a repeatable, pinned and reviewed local verifier setup (helper, NVIDIA verifier, its execution image, local Docker daemon);
  3. the two documentation corrections D1–D2 below.
- The setup delta must be reviewed before `PUBLIC_BUILD_PROFILE_ENABLED` is flipped. The current execution image `sha256:b67dad12…` is not reproducible, so it is not yet a qualified local artifact.

## Resolution of prior findings

| Prior | Status | Evidence |
| --- | --- | --- |
| F1 subject ↔ predicate ↔ quote | **Resolved** | Details below. |
| F2 frozen GPU versions | **Resolved** | [`gpuVersionsAllowed`](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/gpu-policy.ts#L12-L16): in `public-builds`, any driver/VBIOS at or above the floors that also passes NVIDIA signed-reference matching, RIM version match and three good nonce-matching OCSP responses ([intel-appraisal.ts#L102-L111](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/intel-appraisal.ts#L102-L111)). Frozen mode keeps exact pins. |
| F3 Node-chain negatives | **Resolved** | [public-build-chain.test.ts](https://github.com/ariofrio/pi-tee/blob/da48839/tests/public-build-chain.test.ts): every delivered artifact bit-flipped through the real helper, plus parent/candidate/config substitutions, a warm-cache nonce-replay rejection and helper-replacement isolation. It skips without the private CPU fixture; the parent reports a fixture run with no skips. |
| F4 per-request downloads | **Resolved** | Process-local bounded cache keyed by digest or immutable URL and namespaced by helper digest. It never stores CPU, GPU, freshness or key results, and is cleared on any failure ([public-build.ts#L14-L44](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/public-build.ts#L14-L44), [#L226-L227](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/public-build.ts#L226-L227)). |
| F5 floor aliasing | **Resolved** | [`floorTDXArtifact`](https://github.com/ariofrio/pi-tee/blob/da48839/tools/tinfoil-public-build/release.go#L75-L99) re-parses an owned copy; [policy_test.go](https://github.com/ariofrio/pi-tee/blob/da48839/tools/tinfoil-public-build/policy_test.go) checks raised floors and an unaltered publisher input; `verify` uses the copy ([main.go#L153](https://github.com/ariofrio/pi-tee/blob/da48839/tools/tinfoil-public-build/main.go#L153)). |
| F6 platform/freshness certificates | **Resolved** | [`requirePublicWorkflow`](https://github.com/ariofrio/pi-tee/blob/da48839/tools/tinfoil-public-build/main.go#L66) applied to the platform, code-freshness and platform-freshness bundles ([main.go#L126](https://github.com/ariofrio/pi-tee/blob/da48839/tools/tinfoil-public-build/main.go#L126), [#L142](https://github.com/ariofrio/pi-tee/blob/da48839/tools/tinfoil-public-build/main.go#L142)). |
| F7 lenient JSON | **Resolved** | [`strictDecode`](https://github.com/ariofrio/pi-tee/blob/da48839/tools/tinfoil-public-build/json.go#L16): duplicates rejected at every depth, case variants rejected, unknown members rejected except in explicit OCI/SLSA projections. Tested with duplicate and case-variant inputs ([runtime_test.go](https://github.com/ariofrio/pi-tee/blob/da48839/tools/tinfoil-public-build/runtime_test.go)). |
| F8 hash-then-execute | **Resolved** | The helper bytes are read once, compared with the pin, written to a private `0700` directory and executed from there ([public-build.ts#L92-L98](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/public-build.ts#L92-L98)). The NVIDIA verifier bytes are snapshotted the same way before the bind mount ([intel-appraisal.ts#L67-L96](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/intel-appraisal.ts#L67-L96)). |
| F9 no authenticated end-of-stream | Unchanged, informational | Output correctness is outside the claim; TLS is pinned to the attested key. |

**F1 resolution in detail.**

- `codePredicate` decodes the DSSE payload strictly and requires its registers and VM shape to equal the measurement tinfoil-go used for the quote. `authenticateDeployment` then requires the strictly decoded subject to equal that predicate field for field ([release.go#L32-L73](https://github.com/ariofrio/pi-tee/blob/da48839/tools/tinfoil-public-build/release.go#L32-L73)).
- `verify` emits RTMR1, RTMR2, the VM shape and the statement digest from the CPU-accepted predicate ([main.go#L164](https://github.com/ariofrio/pi-tee/blob/da48839/tools/tinfoil-public-build/main.go#L164)).
- Node recomputes RTMR1/RTMR2 against those emitted values ([public-build.ts#L145-L147](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/public-build.ts#L145-L147)). It also requires the same statement digest from `--runtime-config`, `--container-reference` and `--container-build` (L160, L165, L207).
- Exactly one code collateral entry, `id=code` / `reference-values`, is enforced on both sides ([main.go#L97-L109](https://github.com/ariofrio/pi-tee/blob/da48839/tools/tinfoil-public-build/main.go#L97-L109), [public-build.ts#L152-L154](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/public-build.ts#L152-L154)).
- A synthetic subject/predicate mismatch cannot be tested with real signatures, because only the publisher can sign one. That is acceptable: the equality check is cheap and fails closed.

## Session, transport and boot recomputation

**Owned session** ([provider.ts#L164-L203](https://github.com/ariofrio/pi-tee/blob/da48839/packages/core/src/provider.ts#L164-L203))

- Public policy never calls `openSdkTransport`. With no profile it fails with `TEE_PUBLIC_BUILD_DEPLOYMENT_UNAVAILABLE`.
- Before inference, the admission must match the profile ID, model, authority-policy digest and all artifact digests, satisfy the time bounds and use the canonical base URL.
- Expiry and the policy epoch are checked again at the final send boundary, after Pi payload hooks. A policy change aborts active requests.
- Tests use the native provider seam: [public-session.test.ts](https://github.com/ariofrio/pi-tee/blob/da48839/tests/public-session.test.ts) covers six admission mismatches, expiry during `onPayload`, and SDK fallback being impossible.
- The production profile cannot be enabled through the environment: [`PUBLIC_BUILD_PROFILE_ENABLED = false`](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/public-policy.ts#L38), wired only through [index.ts#L54](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/index.ts#L54). Only the research harness constructs the profile directly ([live-pi.ts#L33](https://github.com/ariofrio/pi-tee/blob/da48839/scripts/live-pi.ts#L33)).

**Key binding.** [`INTEL_PUBLIC_BUILD_PROFILE.openSession`](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/intel.ts#L14-L31) creates the transport from the same appraisal's quote-bound TLS SPKI and HPKE key. The design is unchanged: send once, TLS 1.3 SPKI pin before credentials, EHBP, fresh `cache_salt`.

**Admission lifetime.** It is the minimum of 60 s after the check, 300 s after the challenge, and seven days after each freshness witness ([intel-appraisal.ts#L123-L126](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/intel-appraisal.ts#L123-L126)).

**Boot recomputation** ([boot-measurements.ts](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/boot-measurements.ts))

- The outputs are compared only with quote-bound signed registers. A porting error can therefore only cause a false rejection (an availability failure); a false acceptance would require a SHA-384 second preimage.
- What the recomputation adds: it binds the downloaded kernel, initrd and exact non-debug command line (config hash and guest verity root) to the running quote. That is what makes the runtime-profile and OCI checks apply to the attested workload.

**Local GPU verifier location.** The Docker context must resolve to the user's local Docker Desktop or OrbStack socket, and `--host` is passed explicitly ([intel-appraisal.ts#L60-L65](https://github.com/ariofrio/pi-tee/blob/da48839/packages/tinfoil/src/intel-appraisal.ts#L60-L65)). Tests reject `ssh`, `tcp` and unapproved Unix endpoints before any evidence fetch ([intel-runtime.test.ts](https://github.com/ariofrio/pi-tee/blob/da48839/tests/intel-runtime.test.ts)).

## Remaining items

| # | Severity | Item | Correction |
| --- | --- | --- | --- |
| D1 | Low (claim) | [SECURITY.md#L3](https://github.com/ariofrio/pi-tee/blob/da48839/SECURITY.md#L3) still says reports mark `publicBuildVerification` and `closedTrustSet` as `not-established`; the provider can now report `profile-established` ([provider.ts#L108-L112](https://github.com/ariofrio/pi-tee/blob/da48839/packages/core/src/provider.ts#L108-L112)). | State that only an enabled public-build profile reports `profile-established`, and that it means the declared profile contract was satisfied for that dispatch. |
| D2 | Low (claim) | [design.md#L77](https://github.com/ariofrio/pi-tee/blob/da48839/docs/design.md#L77) says the admission contains "endpoint keys" and "established properties"; [`PublicBuildAdmission`](https://github.com/ariofrio/pi-tee/blob/da48839/packages/core/src/provider.ts#L16-L27) contains neither. The keys are bound by construction inside `openSession`, so this is wording only. | Either add the TLS SPKI and HPKE fingerprints to the admission (cheap, and useful for auditing) or drop the words. |
| D3 | Info (claim wording) | `closedTrustSet: "profile-established"` covers a local closure the client cannot enumerate: "enabled extensions/hooks/tools" ([tinfoil-public-profile.md](https://github.com/ariofrio/pi-tee/blob/da48839/docs/tinfoil-public-profile.md)). | Describe it as *declared* closure in the report docs. No code change is needed. |
| D4 | Low (availability) | OCI index and image manifests use non-projection strict decoding ([container.go#L111](https://github.com/ariofrio/pi-tee/blob/da48839/tools/tinfoil-public-build/container.go#L111)). A future valid top-level member such as `annotations`, `artifactType` or `subject` would fail closed. | Optionally decode OCI documents as projections; case variants and duplicates stay rejected. |
| D5 | Info | The `immutable:` cache keys cover discovery URLs that are not content-addressed (the GitHub attestation list and the CVM manifest by version name). This is safe because their contents are verified downstream and any failure clears the cache. | Rename the key prefix, or document that it means "verified-before-use discovery". |
| D6 | Info (doc wording) | The profile doc says "The host's egress-capable services remain trusted guest processes." | Write "the guest's egress-capable services". |

## Profile contract claims checked against pinned sources

These are publisher or manufacturer software contracts, supported by source at cvmimage [`a4dbce0`](https://github.com/tinfoilsh/cvmimage/tree/a4dbce07f5b0efbee1df678026db538eba66a613). None of them is a live observation.

- **Credential recipient.** The shim's API-key validation sends `api_key`, `domain`, `requested_host` and `path` to the control plane, without the request body ([key.go#L9-L15](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/key/key.go#L9-L15), [api.go#L238-L257](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/shim/api.go#L238-L257)).
  - The control plane defaults to `https://api.tinfoil.sh` ([config.go#L28](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/config/config.go#L28)). The runtime profile cannot override it, because its `shim` schema has no `control-plane` field.
  - JWT access tokens are validated locally against a JWKS ([shim main.go#L198-L222](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/shim/main.go#L198-L222)).
  - The profile doc's "intended credential recipient" classification is accurate.
- **RAM-backed state.** Docker `data-root` and containerd `root`/`state` are under `/mnt/ramdisk/private` ([daemon.json](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/image/rootfs/etc/docker/daemon.json), [containerd config](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/image/rootfs/etc/containerd/config.toml#L28-L29)). The ramdisk is tmpfs ([setup.go#L125-L146](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/pid1/runtime/setup.go#L125-L146)).
- **Production console.** The release workflow builds `shipping-image` ([release.yml](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/.github/workflows/release.yml)). That image uses the non-debug `kernel`, which selects `20-production-console.config`; `debugConsole=true` applies only to the separate `debug-image` ([default.nix#L22-L69](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/default.nix#L22-L69), [kernel.nix#L12-L20](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/nix/kernel.nix#L12-L20)). The claim is supported for the attested shipping kernel; RTMR1 now binds the kernel bytes.
- **Boot gating.** The shim enables the proxy only after boot stages finish and none failed ([shim main.go#L185-L195](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/shim/main.go#L185-L195)).
- **Keys, egress, upstream, module lock, driver fatal state.** Already verified in the prior review and still accurate: guest-generated per-boot keys in the private RAM directory, closed shim network, fixed upstream `172.31.255.2`, `modules_disabled` blocking unload, and fatal state that cannot be cleared.
- **Unsupported or overreaching claims:** none beyond D1–D3 and D6. The profile doc correctly labels the GPU reset, channel and key-custody semantics as manufacturer and publisher contracts rather than measurements.

## Live observations versus my own verification

- **Reported by the parent, not repeated by me:** the actual Pi completion, tools, follow-up, reasoning, usage, login and cancellation suite; the independent live-delta cancellation; 60/60 tests with private fixtures; the live fresh-challenge request counts.
- **Verified by me, offline only.** No inference, no live evidence, no secrets.
  - Rebuilding the helper from the `da48839` snapshot (`GOTOOLCHAIN=go1.26.6 -trimpath -buildvcs=false`) reproduces the pin `08bcbf2f96f01d46c4129c0cca2e9135e76c44e1710bc51ff5cbc0652c7af1ba`.
  - `go test ./...` passes.
  - Isolated build, typecheck and `node --test tests/*.test.ts` on the snapshot: 60 tests, 57 pass, 3 skipped (private fixtures), 0 fail. These ran on Node 26.10.0 because Node 24 was unavailable locally.

## Answer: limited macOS ARM64 production scope

Under the accepted policy, the remote-side security of that scope is fully established by the reviewed code and the declared contracts. The client-side prerequisites are:

1. **Repeatable local verifier artifacts.**
   - The public-build helper is reproducible from source (verified above).
   - The NVIDIA verifier archive is pinned to NVIDIA's published hashes.
   - The **GPU-verifier execution image** must become reproducible or otherwise pinned and reviewed. It decides the GPU verdict, so it belongs in the trusted local inventory. This is the parent's in-progress setup work, and it needs its own review before the flag is enabled.
2. **Honest support limits.** The supported environment is macOS ARM64 with a local Docker Desktop or OrbStack daemon. Other platforms fail with `TEE_RUNTIME_UNSUPPORTED` and keep the explicit SDK routes.
3. **Documentation fixes D1–D2.** D3 and D6 are optional wording.

Nothing else is required. In particular, no additional client mechanism, hardware experiment or per-release review is needed.

## NEAR

`packages/nearai` is unchanged in `205b1af..da48839`. The client-solvable versus server-only split in the prior review stands. Keep the NEAR public profile gated; a client-only exporter protocol cannot qualify the deployed servers, which still share keys and lack exporter binding, KMS/runtime evidence and CPU–GPU binding.

Written by Claude Opus 5.5.
