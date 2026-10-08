# pi-tinfoil

Tinfoil provider extension for Pi 1.0.4. Supports native API-key `/login tinfoil`, `TINFOIL_API_KEY`, live chat/tool model discovery, thinking controls, Pi tools/usage and EHBP encryption. Stored Pi credentials take precedence over environment keys. Browser OAuth is not implemented.

Build from the repository's locked Node 24 workspace, then load `dist/extension.js` with `pi -e`. The shared `pi-tee-core` dependency is not another extension. This package does not load NEAR's SDK. Registry publication has not occurred; fresh tarball installs may resolve different SDK dependencies.

## Public builds

The default policy is `public-builds`, and the default route is `auto`. Public admission currently exposes no models while the GPU verifier is replaced and requalified. The paused Gemma chain authenticates fresh Intel TDX evidence, the exact CPU-bound NVIDIA report, named public workload/guest/platform/freshness workflows, dynamic guest/OCI/model roots and the constrained runtime configuration. Boot registers are recomputed against quote-bound signed values. NVIDIA driver/VBIOS updates require signed references and revocation checks above local floors (`595.71.05`, `96.00.D9.00.02`); compatible releases need no maintained deployment pins. [Artifact chain](src/public-build.ts), [appraisal](src/intel-appraisal.ts).

The supported client setup is macOS ARM64, Node 24, OrbStack, Docker 29.4.0, buildx 0.33.0 and the containerd image store. Only this setup has been tested end to end. The local socket guard recognizes Docker Desktop, but its setup is unvalidated. Classic image stores and incompatible builders fail closed. Remote Docker contexts are rejected before collecting evidence. The local OS, clock, CLI and daemon remain trusted. [Setup inventory and reproducibility](../../docs/intel-candidate.md#local-setup).

Run the packaged `pi-tinfoil-setup --directory ABSOLUTE_PATH` command (or `node dist/setup.js` from this package). It authenticates fixed NVIDIA/Ubuntu artifacts, rebuilds the locked Go helper, verifies the entire reproducible image archive before loading, and prints the paths to configure:

```sh
export PI_TINFOIL_PUBLIC_BUILD_VERIFIER=/absolute/local-verifiers/tinfoil-public-build-verifier
export PI_TINFOIL_NVAT_DIR=/absolute/local-verifiers/libnvat-linux-sbsa-1.2.2.1780962352-archive
pi -e /absolute/pi-tinfoil/dist/extension.js
```

The extension never downloads executables itself or substitutes an unpinned helper/image. Missing helpers and unsupported platforms reject before inference. Helpers receive public evidence, not API keys or prompts; owner-only evidence files and executable snapshots are removed after appraisal. A bounded process-local cache retains authenticated artifacts and deterministic helper results; fresh hardware evidence, keys and freshness acceptance are never cached.

The owned session binds authority/artifact digests and short-lived appraisal to one TLS 1.3 socket before transmitting credentials or EHBP ciphertext. It sends once, rejects rotation/reconnect/resend and uses a fresh encrypted vLLM cache salt. Admission expiry and policy epoch are checked again after payload hooks. Public policy has no SDK fallback. [Session](src/intel.ts), [transport](src/direct.ts), [socket binding](../core/src/pinned-tls.ts).

`/tinfoil status` reports `profile-established` verification after a successful public dispatch and `profile-declared` trust closure. The [serving contract](../../docs/tinfoil-public-profile.md) names all accepted public software/manufacturer authorities, plaintext/key-capable processes and operator inputs. Publishers are trusted for safe software and correct measurements; this is neither manufacturer-only trust nor independent per-release review. `independentApproval` and `protectedSession` remain `not-established`. Other Pi providers, tools and extensions can access the conversation.

## Policy and alternative routes

`PI_TINFOIL_POLICY` and `/tinfoil policy` accept `public-builds`, `sdk` and `approved`. Policy changes abort active requests and are not persisted. `approved` has no implemented profile. `/tinfoil models`, `/tinfoil models refresh` and `/tinfoil status` inspect discovery/reporting; `PI_TEE_OFFLINE=1` restores Pi's catalog snapshot without startup discovery.

Maintainers can run `npm run smoke:workers` in the locked checkout to discover and collect nonce-bearing public evidence from every advertised worker for the current seven chat workloads. The [discovery module](src/worker-discovery.ts) fixes the delivery services and confines candidates to the Tinfoil worker namespace; the caller supplies its expected publisher repository. It ignores delivery-supplied keys and measurements. The probe reports unverified evidence, never sends inference, and does not alter production routing. `-- --save-evidence` saves private research captures under ignored `.scratch/work/worker-discovery-evidence` with owner-only permissions.

Routes are selected at startup:

| `PI_TINFOIL_ROUTE` | Behavior |
| --- | --- |
| `auto` | Default. Public builds are paused. Explicit SDK policy uses the router catalog. |
| `direct-public` | Same public profile; in SDK policy exercises the dynamic Intel appraiser as an experimental route. |
| `router` | SDK policy only. Tinfoil 1.2.2 verifies the router with AMD Genoa/Sigstore tagged-release rules, no AMD revocation or rollback floor. It trusts backend/hardware release authorities and can re-attest/resend on rotation. [SDK recovery](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts#L370). |
| `direct` | SDK policy only. Frozen AMD Gemma worker/artifact/measurement, owned TLS/EHBP send-once transport; no fresh v3, AMD revocation or independent GPU appraisal. [Assessment](../../docs/direct-access.md). |
| `direct-intel` | SDK policy only. Frozen Intel/GPU policy, configured `PI_TINFOIL_CPU_VERIFIER` and NVIDIA helper, send-once transport. These fixture pins do not constitute independent approval. [Inventory](../../docs/intel-candidate.md). |

Caller URL/header/fetch overrides, hosted tools, remote media and unclassified fields are rejected at the final serialized request boundary. Pi provider retries are disabled and security failures use terminal codes. The router's disclosed SDK resend remains confined to SDK policy.

The actual production public-policy Pi suite covers native secret login, stored-key precedence, completion/usage, Unicode tools and follow-up, reasoning, RPC cancellation and separate live-delta cancellation with the packaged verifiers. Cancellation establishes local abort/acknowledgement, not the remote engine's stop time. [Live harness and validation](../../README.md#validation).

Written by Codex.
