# NEAR AI and Tinfoil providers for Pi

Design updated 2026-10-07. The normal target is automatic verification of public builds, selected by the project owner. The earlier [Opus 5.5 review](design-review.md) and [resolutions](review-resolution.md) cover the original independent-approval design; they do not review this policy revision or its implementation.

## Policy

`public-builds` is the default. A fixed set of public publishers and build workflows authorizes software releases; authenticated release measurements select the expected running workload automatically. A new release does not require updating deployment hashes in the extension. Exact artifact hashes still matter for each verification, but are recovered from authenticated evidence rather than maintained as a vendor deployment catalog.

This policy trusts the designated source maintainers, workflow writers and build processes to publish safe software and correct measurements. Those authorities may be operated by the inference provider. Provider infrastructure cannot substitute arbitrary software solely through DNS, a catalog, a proxy or a deployment instruction. A malicious authorized public release can nevertheless be accepted before anyone notices it. Public evidence makes later auditing possible; it does not ensure detection.

Three settings are explicit:

| Policy | Software authorization | Current inference availability |
| --- | --- | --- |
| `public-builds` | Named public publisher/workflow identities, authenticated artifacts and fresh endorsements; complete hardware and serving-path requirements still apply. | Blocked until a full serving profile passes the remaining gates. |
| `sdk` | The selected route's disclosed SDK/candidate rules. | Experimental routes documented in the package READMEs. |
| `approved` | Optional independent approval of a frozen workload. | No implemented profile. Retained for compatibility; no maintained vendor pin catalog is planned. |

Optional frozen workloads would use user-supplied manifests. Existing pinned workers and helper policies remain research fixtures for the explicit experimental routes. They are not the normal update mechanism. No policy falls back to `sdk` after failure, and no result is labeled “fully TEE verified.”

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

The [probe inventory](../tools/tinfoil-public-build/README.md) records exact root hashes and dependency versions. It does not appraise a GPU or authorize inference, so NVIDIA and the full container/model build closure have not yet been qualified by this probe. GitHub is additionally trusted to serve public source for the configuration comparison; signed subject digests authenticate downloaded deployment and guest artifact bytes.

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

The [guest-build verifier](../tools/tinfoil-public-build/cvm.go) also authenticates the guest manifest/kernel/initrd/disk subjects, exact release workflow and source commit. The live probe checks kernel/initrd bytes, the manifest's guest verity root and exact non-debug command line, then recomputes RTMR1/RTMR2. This establishes CPU/public-release/build attribution, not an independent reproducible image build. The authenticated OCI metadata/public source and dynamic model-pack roots are now checked with a constrained runtime configuration. Complete running engine/GPU/channel/reset/key qualification plus review remain required before `public-builds` exposes models. The earlier [boot and runtime assessment](tinfoil-workload.md) and [Intel candidate](intel-candidate.md) provide source and real-hardware evidence for that work.

A direct connection avoids a decrypting router's additional recipients and backend-update logic. The stock Tinfoil JavaScript SDK only verifies AMD Genoa, omits AMD revocation, and can re-attest and resend on rotation. The experimental Intel routes use local Intel/NVIDIA appraisal and a send-once encrypted transport. `direct-intel` retains frozen CPU policy; `direct-public` verifies fresh dynamic release/guest/OCI/source/runtime artifacts first. The latter passed the full actual Pi suite and separate live-delta cancellation, but uses manufacturer-authenticated driver/VBIOS references above local version floors and has no completed production public-build admission. [SDK resend](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts#L370), [current appraisal](../packages/tinfoil/src/intel-appraisal.ts), [transport](../packages/tinfoil/src/direct.ts).

A router can be admitted later only if its measured code enforces the chosen public publisher/freshness/hardware policy on each actual downstream request, including sidecars and fallback. Polling a status endpoint before dispatch is insufficient. Backend updates within named public identities can be acceptable, but the client must know the enforced downstream contract. [Router update logic](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/manager/manager.go#L929), [conditional sidecar](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/safeguards/capture.go#L44).

NEAR still needs server support. Instances with different measurements share a model signing identity. Shared TLS keys also allow another key holder to relay a fresh quote from an acceptable instance. Neither another quote nor a matching response signature identifies the instance serving the request. A measured TLS terminator could bind its own connection exporter, local nonce and serving-policy commitment into the CPU quote; the client would compare its socket's exporter before sending inference. Quoting a caller-supplied exporter would remain relayable. This is a proposed protocol, not an existing NEAR capability. [Shared signer contract](https://docs.near.ai/cloud/verification/cloud-api/model-attestations), [TLS exporter](https://www.rfc-editor.org/rfc/rfc9266.html#section-2).

NEAR's SDK does not appraise MRTD/RTMR0–2; its guest-written OS hash depends on key-release policy. Public recipes also contain runtime downloads and privileged/mutable services. A public-build profile must authenticate the full active boot/runtime closure and either eliminate shared-key provisioning dependence or enumerate and verify the deployed KMS, upgrade authority and recipient rules. The existing same-TLS direct GLM route remains an SDK candidate. [Intel adapter](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/utils/intel.ts#L101), [runtime recipe](https://github.com/nearai/cvm-compose-files/blob/cda2032fa8f8638639d858703b6de4d76c2118e8/prod/dsv4-qwen36-gemma4.yaml#L254), [KMS](https://github.com/nearai/near-kms/blob/dd792a9fa228d33c6dbe615646242d20e9d876a4/README.md), [direct channel](../packages/nearai/src/direct-channel.ts).

## Pi integration and request lifecycle

Keep two separately installable provider extensions and one shared library. Native API-key `/login`, stored credentials, live catalogs, four-hour refresh, tools, reasoning, usage and cancellation already work. NEAR's TEE-only visibility filter is independent of security policy; showing a catalog entry never authorizes inference. [Provider interface](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/docs/custom-provider.md), [shared provider](../packages/core/src/provider.ts).

Admission will return an owned session containing the model, stable authority-policy digest, authenticated release digests, endpoint keys, freshness bounds and established properties. The session cannot be changed by catalog metadata, caller URLs/headers/fetch, payload hooks or routing aliases.

1. Select the canonical model and policy; obtain evidence without sending prompts or credentials.
2. Authenticate releases and hardware; establish the complete serving chain before releasing inference keys.
3. Validate Pi's final serialized payload after hooks; reject unclassified fields, hosted tools, remote media and unauthorized outer headers.
4. Bind the actual TLS socket and encrypt supported fields. Send once; a rotation/error does not automatically replay a possibly executed request.
5. Authenticate responses before exposing text or executable tool calls. NEAR buffers bounded response bytes in memory until signature verification. Tinfoil can stream authenticated encrypted chunks.
6. On cancellation, policy change, timeout or integrity failure, close/dispose transport and emit a sanitized terminal error that Pi's retry classifiers do not replay.

Catalog caching is not security caching. Reuse of authenticated evidence must preserve its expiry, nonce/session semantics and current policy epoch; a cached catalog cannot extend admission. Root/authority-policy changes invalidate active sessions. No plaintext evidence upload or background inference is added.

These extensions protect their own dispatches. Whole-session confidentiality additionally needs a Pi guard after resolving the physical provider, covering model switches, virtual fallback, summaries, compaction and background calls. Pi catches request-hook exceptions, so an extension hook alone cannot enforce that boundary. [Hook behavior](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/core/extensions/runner.ts#L1361).

## Validation and next implementation steps

Tests observe native provider/network boundaries, using real cryptography where evidence is available. No mocked success qualifies a production profile. Required negatives include wrong publisher/workflow/root/digest, stale/future witnesses, unauthorized rollback, nonce replay, debug/outdated/revoked CPU, missing or unrelated GPU evidence, wrong TLS/HPKE keys, shared-key relay, mutable runtime inputs, unverified recipients, reconnect/rotation/resend, payload overrides, forged tool output, and cancellation/size/runtime limits.

The unchanged guest-build verifier accepts authentic CVM `v0.11.0` and `v0.14.13` under the same roots/workflow policy, with no deployment-pin edit. [Offline real-signature tests](../tools/tinfoil-public-build/cvm_test.go), [public fixture provenance](../tools/tinfoil-public-build/testdata/README.md). This establishes automatic acceptance at the guest-build stage. The complete serving profile still needs a positive update test across two qualified deployments; independent rebuilding is outside the normal policy requirement.

Next: complete model attribution and full engine/runtime qualification; qualify GPU channel/reset and runtime key/mutation contracts; package the verifier/dependency inventory; wire that admission to the send-once worker transport and exercise the full actual Pi suite. NEAR's missing session-binding/runtime contract must be implemented server-side before an equivalent route can qualify. Independent review of the changed verifier/transport remains a production release gate.

Availability, truthful billing, output correctness, traffic analysis, undocumented physical/side-channel protection and compromise of the user's local machine are outside the claim. Public-source monitoring and independent rebuilds can detect problems, but are not required to authorize each normal release. A frozen user manifest can impose that stricter policy later without making the extension maintain vendor deployment pins.

Written by Codex.
