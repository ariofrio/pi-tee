# Opus 5.5 review: local verifier setup at `c91d3f8`

**Archived review.** Original findings, conditions and verdicts below apply only to the stated scope. [Scope and commit index](README.md) links follow-ups; this is not a review of current `main`. [Original document snapshot](https://github.com/ariofrio/pi-tee/blob/5f561f34e688f49739e3693dbc9a0c32362bcaba/docs/reviews/pi-tee-local-setup-opus-review.md).

**Scope.** Commit [`c91d3f88e4d3e6133cf784b39535e14b91ca3e7e`](https://github.com/ariofrio/pi-tee/commit/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e), the range `da48839..c91d3f8` ("Package repeatable pinned Intel and NVIDIA verifier setup").

**Method.** Reviewed from a `git archive` snapshot.
- I did not review the parent's uncommitted working-tree edits (`provider.ts`, `index.ts`, `intel.ts`, `public-session.test.ts`, presumably the factory route wiring).
- I did not run inference, use secrets or start a Docker build. My checks were offline, plus public registry and archive metadata fetches.

Prior reviews: [public-build](pi-tee-public-build-opus-review.md), [public session](pi-tee-public-session-opus-review.md).

## Verdict

- **No security bug found in the setup.** The pins (sizes and SHA-256 for every input, the complete OCI archive hash, the image ID and the helper hash) fix the bytes the runtime uses, whatever builder produced them.
- **I verified the pinned image's contents independently.** It is exactly the pinned Ubuntu arm64 base, the five Ubuntu-signed packages extracted without maintainer scripts, and the recipe's entrypoint and environment.
- **D1–D6 are resolved.**
- **Before enabling the profile for macOS ARM64:**
  1. Review the change that flips the flag and wires the route on its own.
  2. Document the exact local Docker configuration the pinned image build needs (L1). This is an availability and honest-scope point, not a security gap.

## Independent verification

| Check | Result |
| --- | --- |
| Parent's two clean builds `.scratch/work/nvat-repeatable-{1,2}.tar` | Both SHA-256 `48d8202ed8b45bca8e1f8a7bdb189130d2e519ea1425744603cc9bfa41e7a1d0`, equal to [`GPU_IMAGE_ARCHIVE_SHA256`](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/packages/tinfoil/src/setup-artifacts.ts#L48). |
| OCI layout | `index.json` names a single arm64 manifest `sha256:7648914f…`, equal to `INTEL_CANDIDATE.gpuImage` ([intel-appraisal.ts](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/packages/tinfoil/src/intel-appraisal.ts)). All 5 blobs hash to their names. |
| Base layer | I fetched `ubuntu@sha256:534baea6…` from Docker Hub. Its arm64/v8 manifest `sha256:08571ca1…` has the single layer `sha256:90812e24…`, the image's first layer. |
| COPY layer | Contains exactly `/deps/*.deb` ×5. Each SHA-256 equals its pin in [`GPU_DEPENDENCIES`](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/packages/tinfoil/src/setup-artifacts.ts#L8-L44). |
| Package authenticity | I verified the `noble-updates` and `noble-security` `InRelease` files from `ports.ubuntu.com` with Ubuntu Archive Automatic Signing Key (2018) `F6ECB3762474EDA9D21B7022871920D1991BC93C` ("Good signature"). Each `binary-arm64/Packages.xz` hash is listed in its signed `InRelease`, and all five pinned package SHA-256 values appear in those indices. `liblzma5 5.6.1+really5.4.5` is Ubuntu's reverted, non-backdoored version. |
| RUN layer | 193 entries, all under `usr/` and `etc/`, plus the `/deps` whiteout. The only new executables are `update-ca-certificates` and a documentation example; no setuid bits. Adds `/etc/ssl/certs/ca-certificates.crt`. |
| Image config | `Entrypoint` and `LD_LIBRARY_PATH` match the recipe; `created` is epoch 0; there are no provenance or SBOM attestations. The embedded [`GPU_DOCKERFILE`](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/packages/tinfoil/src/setup-artifacts.ts#L46) is byte-identical to [tools/tinfoil-gpu/Dockerfile](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/tools/tinfoil-gpu/Dockerfile) and to the parent's build context. |
| NVIDIA archive | Size and SHA-256 `720455eb…` equal NVIDIA's [redistrib 1.2.2 manifest](https://developer.download.nvidia.com/compute/nvat/redist/redistrib_1.2.2.json) and my earlier download. |
| Packaged CPU-verifier source | [`package-verifier-source.mjs`](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/scripts/package-verifier-source.mjs) output (non-test `.go`, `go.mod`, `go.sum`, `trusted_root.json`) builds offline with Go 1.26.6 (`-trimpath -buildvcs=false -p=1`) to `08bcbf2f…`, equal to the pin. |
| `pi-tinfoil-setup --verify-cache-only` | Authentic cache → `PASS`. One-byte-modified `.deb` → `TEE_SETUP_ARTIFACT_REJECTED`. Relative directory → `TEE_SETUP_ARGUMENT_REJECTED`. |
| Snapshot tests | Isolated build and typecheck pass. 61 tests: 57 pass, 3 skipped (private fixtures), 1 failure caused by my environment (L2). I used Node 26.10.0 because the pinned Node 24 is unavailable here. |

## Setup design assessment

**[setup.ts](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/packages/tinfoil/src/setup.ts)**

- **Downloads.** Fixed URLs, `redirect: "error"`, streaming size cap, then exact size and SHA-256. A substituted cached file fails closed.
- **CPU helper.** The output hash is pinned, so the Go toolchain, module proxy and the user's `GOENV` can only affect availability.
- **NVIDIA library.** Hashed after extraction in scratch.
- **GPU image.**
  - The image builds from a mode-normalized context.
  - `buildx --network=none --no-cache` with `SOURCE_DATE_EPOCH=0`, `rewrite-timestamp=true`, no provenance and no SBOM.
  - The whole archive is hash-checked *before* `docker load`, and the loaded image ID is checked afterwards.
- **Runtime.** The runtime still re-hashes and snapshots the NVIDIA files on every appraisal and runs only the content-addressed image ID with `--pull=never`, so the final unhashed `tar -xf` into the setup directory is not trusted on its own.

**Trust inventory.** The remaining trust is local: the OS, the Docker daemon/VM, Node and Go, all in the declared closure. The manufacturer-distributed NVIDIA binary is accepted without an independent rebuild. WebPKI in the image's CA bundle only delivers NVIDIA RIMs and OCSP responses, which are verified against NVIDIA's roots, so it adds no authority.

## Findings

| # | Severity | Finding | Correction |
| --- | --- | --- | --- |
| L1 | Low (availability / honest scope) | The pinned build implicitly requires Docker's **containerd image store** and a BuildKit matching the tested builder.<br>• With the default `docker` driver, `--output type=oci` needs the containerd store.<br>• After `docker load`, `.Id` equals the manifest digest `7648914f…` only under the containerd store; the classic store reports the config digest `bde8ef27…`.<br>• Other BuildKit versions can change the compressed layers.<br>All of these fail closed, as `TEE_SETUP_FAILED` or `TEE_SETUP_VERIFIER_REJECTED`. Yet the docs and runtime accept "Docker Desktop/OrbStack" ([intel-candidate.md](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/docs/intel-candidate.md), [README](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/packages/tinfoil/README.md)), and only OrbStack (Docker 29.4.0 / buildx 0.33.0) was tested ([evidence](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/docs/local-verifier-setup-evidence.json)). | 1. State the tested configuration as the supported one: OrbStack, or Docker with the containerd image store and the tested buildx/BuildKit. Say that other builders fail closed.<br>2. Optionally add a preflight (`docker info` storage driver, `docker buildx version`) that gives a specific error.<br>3. Optionally allow importing the pinned OCI tar from any source. The tar hash is the authority, its contents are fully derived from authenticated inputs, and I verified them above, so letting Docker Desktop users load it without rebuilding adds no trust. |
| L2 | Info (test fragility) | [setup-verifiers.test.ts](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/tests/setup-verifiers.test.ts) compares the whole stderr. Under Node 26, tsx's `module.register()` deprecation warning makes it fail. Not a product bug with the pinned Node 24. | Pass `--no-deprecation`, or assert on the last stderr line. |
| L3 | Info | The COPY layer keeps the five `.deb` files (12.5 MB) beneath a whiteout. Harmless. | Optionally use a `RUN --mount=type=bind` context in a later image revision. This changes the pins. |
| L4 | Info | Setup does not apply the runtime's local-Docker-context restriction. Integrity is unaffected (archive hash before load, image ID after), and runtime appraisal rejects remote contexts anyway. | None required. |

**Resolution of the prior review's D1–D6**

- **D1 resolved.** [provider.ts](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/packages/core/src/provider.ts) reports `publicBuildVerification: profile-established` and `closedTrustSet: profile-declared`, and [SECURITY.md#L3](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/SECURITY.md#L3) matches.
- **D2 resolved.** [design.md](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/docs/design.md) places the keys in the owned transport.
- **D3 and D4 resolved.** [tinfoil-public-profile.md](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/docs/tinfoil-public-profile.md) covers the declared closure and the client-policy update for schema or GPU-family expansion.
- **D5 resolved.** Discovery that is verified before use is documented in [tools README#L66](https://github.com/ariofrio/pi-tee/blob/c91d3f88e4d3e6133cf784b39535e14b91ca3e7e/tools/tinfoil-public-build/README.md#L66).
- **D6 resolved.** "guest's" wording fixed.

## Remaining conditions before enabling the first public profile (macOS ARM64)

1. **Review the enablement change on its own.** This covers `PUBLIC_BUILD_PROFILE_ENABLED` and the route/factory wiring now in the parent's uncommitted working tree. It must keep:
   - no environment override;
   - no SDK fallback;
   - the session checks reviewed at `da48839`.
2. **Document the supported local Docker/builder configuration (L1).** Optionally add a preflight or a pinned-tar import path.

Not required, and not raised:
- independent rebuild of NVIDIA's binary;
- physical or reset experiments;
- per-release audits;
- cross-platform reproducibility. Other platforms keep the explicit SDK routes.

NEAR remains gated as before.

Written by Claude Opus 5.5.
