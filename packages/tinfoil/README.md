# pi-tinfoil

Tinfoil provider extension for Pi 1.0.4. Supports native API-key `/login tinfoil`, `TINFOIL_API_KEY`, live chat/tool model discovery, thinking controls, Pi tools/usage and EHBP encryption. Stored Pi credentials take precedence over environment keys. Browser OAuth is not implemented.

Build from the repository's locked Node 24 workspace, then load `dist/extension.js` with `pi -e`. The shared `pi-tee-core` dependency is not another extension. This package does not load NEAR's SDK. Registry publication has not occurred; fresh tarball installs may resolve different SDK dependencies.

## Public builds

The default policy is `public-builds`, and the default route is `auto`. Public admission currently exposes no models while its WebAssembly verifiers await independent review; the experimental `sdk`-policy `direct-public` route runs the same appraisal meanwhile. It covers Gemma 4 31B, DeepSeek V4.1 Flash and GLM-5.3, whose workers accept direct connections. Each dispatch discovers workers and appraises a candidate freshly. The chain authenticates fresh Intel TDX or AMD SEV-SNP evidence and every CPU-bound NVIDIA report. It also checks the named public workload/guest/platform/freshness workflows, dynamic guest/OCI/model roots and the constrained runtime configuration. Boot measurements are recomputed against quote-bound signed values. One Hopper GPU must report SPT; several Blackwell GPUs must report MPT. NVIDIA driver/VBIOS updates require signed references and revocation checks above per-model floors; compatible releases need no maintained deployment pins. [Artifact chain](src/public-build.ts), [appraisal](src/worker-appraisal.ts), [GPU policy](src/gpu-policy.ts).

No setup is needed. The CPU/release verifier and NVIDIA's verifier ship in [`wasm/`](wasm) and run on every Pi platform, under Node and Bun. The extension checks each module's SHA-256 before compiling it and runs it in a worker thread that cancellation terminates. The CPU verifier has no file system or network; the NVIDIA verifier can reach only NVIDIA's reference-manifest and OCSP services. Neither receives API keys or prompts. A bounded process-local cache retains authenticated artifacts and deterministic helper results; fresh hardware evidence, keys and freshness acceptance are never cached. [Recipe and runtime boundary](../../tools/nvidia-verifier/README.md).

The owned session binds authority/artifact digests and short-lived appraisal to one TLS 1.3 socket before transmitting credentials or EHBP ciphertext. It sends once, rejects rotation/reconnect/resend and uses a fresh encrypted vLLM cache salt. Admission expiry and policy epoch are checked again after payload hooks. Public policy has no SDK fallback. [Session](src/public-session.ts), [transport](src/direct.ts), [socket binding](../core/src/pinned-tls.ts).

`/tinfoil status` reports `profile-established` verification after a successful public dispatch and `profile-declared` trust closure. The [serving contract](../../docs/tinfoil-public-profile.md) names all accepted public software/manufacturer authorities, plaintext/key-capable processes and operator inputs. Publishers are trusted for safe software and correct measurements; this is neither manufacturer-only trust nor independent per-release review. `independentApproval` and `protectedSession` remain `not-established`. Other Pi providers, tools and extensions can access the conversation.

## Policy and alternative routes

`PI_TINFOIL_POLICY` and `/tinfoil policy` accept `public-builds`, `sdk` and `approved`. Policy changes abort active requests and are not persisted. `approved` has no implemented profile. `/tinfoil models`, `/tinfoil models refresh` and `/tinfoil status` inspect discovery/reporting; `PI_TEE_OFFLINE=1` restores Pi's catalog snapshot without startup discovery.

Maintainers can run `npm run smoke:workers` in the locked checkout to discover and collect nonce-bearing public evidence from every advertised worker for the current seven chat workloads. The [discovery module](src/worker-discovery.ts) fixes the delivery services and confines candidates to the Tinfoil worker namespace; the caller supplies its expected publisher repository. It ignores delivery-supplied keys and measurements. The probe reports unverified evidence, never sends inference, and does not alter production routing. `-- --save-evidence` saves private research captures under ignored `.scratch/work/worker-discovery-evidence` with owner-only permissions.

Routes are selected at startup:

| `PI_TINFOIL_ROUTE` | Behavior |
| --- | --- |
| `auto` | Default. Public builds are paused. Explicit SDK policy uses the router catalog. |
| `direct-public` | Same public profile. Under `sdk` policy it runs the full public-build appraisal as an experimental route while production admission awaits review. |
| `router` | SDK policy only. Tinfoil 1.2.2 verifies the router with AMD Genoa/Sigstore tagged-release rules, no AMD revocation or rollback floor. It trusts backend/hardware release authorities and can re-attest/resend on rotation. [SDK recovery](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts#L370). |
| `direct` | SDK policy only. Frozen AMD Gemma worker/artifact/measurement, owned TLS/EHBP send-once transport; no fresh v3, AMD revocation or independent GPU appraisal. [Assessment](../../docs/direct-access.md). |

Caller URL/header/fetch overrides, hosted tools, remote media and unclassified fields are rejected at the final serialized request boundary. Pi provider retries are disabled and security failures use terminal codes. The router's disclosed SDK resend remains confined to SDK policy.

The actual Pi suite on the `direct-public` route covers native secret login, stored-key precedence, completion/usage, Unicode tools and follow-up, reasoning and RPC cancellation for all three models under the Node CLI. Gemma also passed live-delta cancellation and the Bun-compiled Pi binary. Cancellation establishes local abort/acknowledgement, not the remote engine's stop time. [Live harness and validation](../../README.md#validation).

Written by Codex and Claude.
