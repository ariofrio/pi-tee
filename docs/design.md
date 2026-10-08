# NEAR AI and Tinfoil providers for Pi

Design updated 2026-10-07. The normal target is automatic verification of public builds, selected by the project owner. The earlier [Opus 5.5 review](design-review.md) and [resolutions](review-resolution.md) cover the original independent-approval design; they do not review this policy revision or its implementation.

## Policy

`public-builds` is the default. A fixed set of public publishers and build workflows authorizes software releases; authenticated release measurements select the expected running workload automatically. A new release does not require updating deployment hashes in the extension. Exact artifact hashes still matter for each verification, but are recovered from authenticated evidence rather than maintained as a vendor deployment catalog.

This policy trusts the designated source maintainers, workflow writers and build processes to publish safe software and correct measurements. Those authorities may be operated by the inference provider. Provider infrastructure cannot substitute arbitrary software solely through DNS, a catalog, a proxy or a deployment instruction. A malicious authorized public release can nevertheless be accepted before anyone notices it. Public evidence makes later auditing possible; it does not ensure detection.

Three settings are explicit:

| Policy | Software authorization | Current inference availability |
| --- | --- | --- |
| `public-builds` | Named public publisher/workflow identities, authenticated artifacts and fresh endorsements; complete hardware and serving-path requirements still apply. | None; Tinfoil Gemma is paused pending GPU verifier requalification. NEAR blocked. |
| `sdk` | The selected route's disclosed SDK/candidate rules. | Experimental routes documented in the package READMEs. |
| `approved` | Optional independent approval of a frozen workload. | No implemented profile. Retained for compatibility; no maintained vendor pin catalog is planned. |

Optional frozen workloads would use user-supplied manifests. Existing pinned workers and helper policies remain research fixtures for the explicit experimental routes. They are not the normal update mechanism. No policy falls back to `sdk` after failure, and no result is labeled “fully TEE verified.”

## Client portability

The client target covers Pi's macOS/Linux/Windows x64 and ARM64 releases, Android/Termux, and both Node and Bun runtimes, without a container runtime or user-installed compiler. Both local verifiers ship as hash-checked WebAssembly, and the TLS transport uses only `node:tls`. [Portable verification](portable-verification.md).

## Trust declarations

The local policy fixes authorities and verification rules; release evidence fixes the artifact bytes used in one session. Changing a repository, workflow path, attestation root, required security property or authorized recipient requires an explicit policy change. Ordinary releases within an accepted identity can update automatically.

| Component | Trusted authority or process |
| --- | --- |
| Local plaintext | The user's OS/runtime, Pi, enabled extensions/hooks/tools, this extension, verifier dependencies and their update process. Their artifact inventory belongs to the client installation. |
| CPU | Accepted Intel or AMD roots, hardware/firmware and endorsement/revocation processes; local clock, security-version floors, debug/migration rules and collateral validity. |
| GPU | Named NVIDIA device/RIM roots and revocation processes, firmware policy, confidential mode and the protected CPU–GPU/fabric implementation. A signed overall verdict alone cannot prove the used channel. |
| Build identity | An exact Sigstore root bundle and its accepted Fulcio, Rekor, CT and timestamp authorities; GitHub Actions OIDC and hosted-runner processes. No provider-supplied trust-root update. |
| Public software | Named source repositories, release workflows, maintainers and workflow writers. Source/build attribution is authorization under this policy; independent review of every release is optional. |
| Firmware references | The named publisher of measured guest firmware/platform references, including its workflow and update process. Manufacturer evidence authenticates the machine; this reference publisher authorizes its expected boot configuration. |
| Freshness | The named signer/process endorsing a release as still acceptable, its validity window and revocation semantics. A publisher can deliberately endorse an older release; fresh endorsement is not a claim that it is newest. |
| Remote recipients | Every process able to decrypt prompts or obtain a serving key, including routers, sidecars, KMS/key-release services and runtime administrators where applicable. These cannot remain implicit. |

For the implemented Tinfoil CPU/public-release probe, the finite remote set is Intel's attestation processes; GitHub Actions OIDC/hosted runners; the keys in the embedded Sigstore root bundle; and these Tinfoil publisher identities:

- `tinfoilsh/confidential-gemma4-31b/.github/workflows/tinfoil-release-publish.yml@refs/tags/vMAJOR.MINOR.PATCH` for workload measurements.
- `tinfoilsh/cvmimage/.github/workflows/release.yml@refs/tags/vMAJOR.MINOR.PATCH` for guest build artifacts and their public source commit.
- `tinfoilsh/platform-endorsements/.github/workflows/build.yml@refs/tags/vMAJOR.MINOR.PATCH` for platform references and machine policy.
- `tinfoilsh/freshness-witness/.github/workflows/freshness.yml@refs/heads/main` for continued acceptance of both artifacts.

The [probe inventory](../tools/tinfoil-public-build/README.md) records exact root hashes and dependency versions. It does not appraise a GPU or authorize inference, so GPU/runtime qualification belongs to the [integrated public profile](tinfoil-public-profile.md), rather than this evidence-only probe. GitHub is additionally trusted to serve public source for the configuration comparison; signed subject digests authenticate downloaded deployment and guest artifact bytes.

The freshness verifier accepts a verified log timestamp at most seven days old and at most five minutes in the future, bound to the exact repository, tag, commit, subject name and digest. This allows continued endorsement of an unchanged worker and mixed deployment versions. It bounds stale evidence to that window; it does not provide immediate revocation or a monotonic newest-release rule. [Freshness implementation](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/provenance/freshness.go).

## Serving-path requirements

Automatic software updates do not relax hardware, custody or channel binding. Before sending an inference body, the client must establish:

1. Fresh CPU evidence with an unpredictable local nonce, manufacturer authentication, valid revocation/collateral, acceptable security versions and non-debug state.
2. Expected guest firmware/OS/configuration/container/model/tokenizer inputs from authenticated public release artifacts. Measured code must authenticate every downloaded runtime input before use; public source for one component cannot authorize an unmeasured downloader or mutable model cache.
3. CPU-bound GPU evidence and an enforced protected path to the devices actually executing inference, including required fabric components, device mode and reset behavior.
4. TLS/HPKE keys confined to the accepted serving environment and retired before an unauthorized runtime mutation. A key shared with an unverified environment cannot establish instance identity.
5. An inference connection bound to those authenticated keys before credentials or ciphertext are sent. Every decrypting hop and downstream dispatch must obey the same policy.

A published implementation of a required check must actually enforce it on the serving path. Signed provenance cannot add a missing GPU channel or session binding. The full local/server input and recipient inventory remains a release gate even though software authorization no longer requires per-release independent approval.

## Provider assessment

Tinfoil's direct Intel worker is the first public-build target. Its live v3 document supplies CPU evidence, software provenance, platform provenance and separate freshness witnesses. The new [evidence-only verifier](../tools/tinfoil-public-build/main.go) authenticates exact release identities and dynamic measurements, applies local TDX floors, then compares the quote's workload and platform registers. It requires UpToDate manufacturer appraisal, revocation and valid collateral. It accepts authenticated updates without a maintained deployment digest. The [public probe](../scripts/research/tinfoil-public-build.mjs) also checks the public deployment bytes against their signed digest and compares its embedded configuration with the source at the authenticated commit.

The [guest-build verifier](../tools/tinfoil-public-build/cvm.go) also authenticates the guest manifest/kernel/initrd/disk subjects, exact release workflow and source commit. The live probe checks kernel/initrd bytes, the manifest's guest verity root and exact non-debug command line, then recomputes RTMR1/RTMR2. This establishes CPU/public-release/build attribution, not an independent reproducible image build. The authenticated OCI metadata/public source and dynamic model-pack roots are now checked with a constrained runtime configuration. The publisher/manufacturer [serving contract](tinfoil-public-profile.md), repeatable local setup and final combined implementation review govern production admission. The [boot and runtime assessment](tinfoil-workload.md) and Intel candidate provide source and real-hardware evidence for that work.

A direct connection avoids a decrypting router's additional recipients and backend-update logic. The stock Tinfoil JavaScript SDK only verifies AMD Genoa, omits AMD revocation, and can re-attest and resend on rotation. The experimental Intel routes use local Intel/NVIDIA appraisal and a send-once encrypted transport. `direct-public` verifies fresh dynamic release/guest/OCI/source/runtime artifacts first, and uses manufacturer-authenticated driver/VBIOS references above local version floors. It passed the full actual Pi suite and live-delta cancellation under Node and Bun. Public-build admission will select it through default `auto` routing once the WebAssembly verifiers are reviewed. [SDK resend](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts#L370), [current appraisal](../packages/tinfoil/src/intel-appraisal.ts), [transport](../packages/tinfoil/src/direct.ts).

A router can be admitted later only if its measured code enforces the chosen public publisher/freshness/hardware policy on each actual downstream request, including sidecars and fallback. Polling a status endpoint before dispatch is insufficient. Backend updates within named public identities can be acceptable, but the client must know the enforced downstream contract. [Router update logic](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/manager/manager.go#L929), [conditional sidecar](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/safeguards/capture.go#L44).

NEAR's SDK routes are implemented; its public-build profile cannot qualify. A root-equivalent compose-manager deploys each worker's serving software at operator-chosen Git refs, with no release signature. That software can use the instance's TLS key and the app-wide KMS signing keys. A client can authenticate past deployments but cannot bound the next one. Chutes-backed models pass through NEAR's plaintext gateway. [NEAR assessment](nearai-status.md).

## Pi integration and request lifecycle

Keep two separately installable provider extensions and one shared library. Native API-key `/login`, stored credentials, live catalogs, four-hour refresh, tools, reasoning, usage and cancellation already work. NEAR's TEE-only visibility filter is independent of security policy; showing a catalog entry never authorizes inference. [Provider interface](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/docs/custom-provider.md), [shared provider](../packages/core/src/provider.ts).

Admission returns an owned session containing the model, stable authority-policy digest, authenticated release digests and freshness bounds, plus a transport constructed from the same appraisal’s quote-bound endpoint keys. The public admission record omits those keys. The session cannot be changed by catalog metadata, caller URLs/headers/fetch, payload hooks or routing aliases.

1. Select the canonical model and policy; obtain evidence without sending prompts or credentials.
2. Authenticate releases and hardware; establish the complete serving chain before releasing inference keys.
3. Validate Pi's final serialized payload after hooks; reject unclassified fields, hosted tools, remote media and unauthorized outer headers.
4. Bind the actual TLS socket and encrypt supported fields. Send once; a rotation/error does not automatically replay a possibly executed request.
5. Authenticate responses before exposing text or executable tool calls. NEAR buffers bounded response bytes in memory until signature verification. Tinfoil can stream authenticated encrypted chunks.
6. On cancellation, policy change, timeout or integrity failure, close/dispose transport and emit a sanitized terminal error that Pi's retry classifiers do not replay.

Catalog caching is not security caching. Reuse of authenticated evidence must preserve its expiry, nonce/session semantics and current policy epoch; a cached catalog cannot extend admission. Root/authority-policy changes invalidate active sessions. No plaintext evidence upload or background inference is added.

These extensions protect their own dispatches. Whole-session confidentiality additionally needs a Pi guard after resolving the physical provider, covering model switches, virtual fallback, summaries, compaction and background calls. Pi catches request-hook exceptions, so an extension hook alone cannot enforce that boundary. [Hook behavior](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/core/extensions/runner.ts#L1361).

## Validation and remaining limits

Tests observe native provider/network boundaries, using real cryptography where evidence is available. No mocked success qualifies a production profile. Required negatives include wrong publisher/workflow/root/digest, stale/future witnesses, unauthorized rollback, nonce replay, debug/outdated/revoked CPU, missing or unrelated GPU evidence, wrong TLS/HPKE keys, shared-key relay, mutable runtime inputs, unverified recipients, reconnect/rotation/resend, payload overrides, forged tool output, and cancellation/size/runtime limits.

The unchanged guest-build verifier accepts authentic CVM `v0.11.0` and `v0.14.13` under the same roots/workflow policy, with no deployment-pin edit. [Offline real-signature tests](../tools/tinfoil-public-build/cvm_test.go), [public fixture provenance](../tools/tinfoil-public-build/testdata/README.md). This establishes automatic acceptance at the guest-build stage. Independent rebuilding, per-release source review and a second live deployment are outside the normal policy requirement.

The [closed serving contract](tinfoil-public-profile.md) records the public publisher, manufacturer, key/runtime and operator assumptions. The owned public-build session now connects that chain to the send-once worker transport, with authority/artifact digests and short-lived expiry checked again after payload hooks. The macOS ARM64 profile, its pinned reproducible local setup and the final route wiring have received independent implementation review. [Session review](reviews/pi-tee-public-session-opus-review.md), [setup review](reviews/pi-tee-local-setup-opus-review.md), [enablement review](reviews/pi-tee-enablement-opus-review.md). The actual-Pi `--public-builds` harness loads the production extension with default `auto` routing; `--public-builds-candidate` remains an isolated adapter test. NEAR [cannot qualify without server changes](nearai-status.md). Independent review of the changed verifier/transport remains a production release gate.

Availability, truthful billing, output correctness, traffic analysis, undocumented physical/side-channel protection and compromise of the user's local machine are outside the claim. Public-source monitoring and independent rebuilds can detect problems, but are not required to authorize each normal release. A frozen user manifest can impose that stricter policy later without making the extension maintain vendor deployment pins.

Written by Codex.
