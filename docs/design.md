# NEAR AI and Tinfoil providers for Pi

Design updated 2026-10-08. The normal target is automatic verification of public builds, selected by the project owner. The earlier [Opus 5.5 review](design-review.md) and [resolutions](review-resolution.md) cover the original independent-approval design; they do not review this policy revision or its implementation.

## Policy

`public-builds` is the default. A fixed set of public publishers and build workflows authorizes software releases; authenticated release measurements select the expected running workload automatically. A new release does not require updating deployment hashes in the extension. Exact artifact hashes still matter for each verification, but are recovered from authenticated evidence rather than maintained as a vendor deployment catalog.

This policy trusts the designated source maintainers, workflow writers and build processes to publish safe software and correct measurements. Those authorities may be operated by the inference provider. Provider infrastructure cannot substitute arbitrary software solely through DNS, a catalog, a proxy or a deployment instruction. A malicious authorized public release can nevertheless be accepted before anyone notices it. Public evidence makes later auditing possible; it does not ensure detection.

Three settings are explicit:

| Policy | Software authorization | Current inference availability |
| --- | --- | --- |
| `public-builds` | Named public publisher/workflow identities, authenticated artifacts and fresh endorsements; complete hardware and serving-path requirements still apply. | Tinfoil Gemma 4 31B, DeepSeek V4.1 Flash and GLM-5.3. NEAR cannot qualify. |
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

For the implemented Tinfoil CPU/public-release verifier, the finite remote set is Intel's and AMD's attestation processes; GitHub Actions OIDC/hosted runners; the keys in the embedded Sigstore root bundle; the pinned SEV-SNP guest firmware; and these Tinfoil publisher identities:

- `tinfoilsh/{confidential-gemma4-31b,confidential-deepseek-v4-1-flash,confidential-glm5-3-nvfp4}/.github/workflows/tinfoil-release-publish.yml@refs/tags/vMAJOR.MINOR.PATCH`, each only for its own model's workload measurements.
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

Tinfoil's direct workers are the public-build target. Their live v3 documents supply CPU evidence, software provenance, platform provenance and separate freshness witnesses. The [evidence verifier](../tools/tinfoil-public-build/main.go) authenticates exact release identities and dynamic measurements and compares the quote's workload and platform measurements. On TDX it applies local floors and requires UpToDate manufacturer appraisal; on SEV-SNP it applies the publisher's TCB floors, AMD's CRL and a non-debug, non-migratable VMPL0 guest policy. It accepts authenticated updates without a maintained deployment digest. The [artifact chain](../packages/tinfoil/src/public-build.ts) also checks the public deployment bytes against their signed digest and compares the embedded configuration with the source at the authenticated commit.

The [guest-build verifier](../tools/tinfoil-public-build/cvm.go) also authenticates the guest manifest/kernel/initrd/disk subjects, exact release workflow and source commit. The client checks kernel/initrd bytes, the manifest's guest verity root and the exact non-debug command line. It then recomputes RTMR1/RTMR2 on TDX, or the full launch digest with the pinned OVMF on SEV-SNP. This establishes CPU/public-release/build attribution, not an independent reproducible image build. Authenticated OCI metadata, public source and dynamic model-pack roots are checked against a constrained runtime configuration. The publisher/manufacturer [serving contract](tinfoil-public-profile.md) and a final combined implementation review govern production admission. The [boot and runtime assessment](tinfoil-workload.md) provides source and real-hardware evidence for that work.

A direct connection avoids a decrypting router's additional recipients and backend-update logic. The stock Tinfoil JavaScript SDK only verifies AMD Genoa, omits AMD revocation, and can re-attest and resend on rotation. `direct-public` rediscovers workers per dispatch and appraises each candidate freshly: release/guest/OCI/source/runtime artifacts, then every CPU-bound GPU against manufacturer-authenticated references above local floors. It uses a send-once encrypted transport. The full actual Pi suite and live-delta cancellation passed for all three models under Node and Bun. Public-build admission selects it through default `auto` routing. [SDK resend](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts#L370), [appraisal](../packages/tinfoil/src/worker-appraisal.ts), [transport](../packages/tinfoil/src/direct.ts).

Tinfoil's other chat models cannot qualify, for reasons a client cannot fix:

| Model | Reason |
| --- | --- |
| `glm-5-3-flash`, `kimi-k3`, `llama3-3-70b`, `gpt-oss-120b` | Their workers refuse direct TCP connections on port 443, from a residential network and from GitHub-hosted runners alike ([runner probe](https://github.com/ariofrio/pi-tee/actions/runs/37720371848), 2026-10-08), so they are reachable only through the router. |
| (router) | EHBP from the SDK terminates at the router enclave, not the model worker: the router decrypts and parses every request, then forwards plaintext over TLS pinned to the worker ([SDK default repo](https://github.com/tinfoilsh/tinfoil-js/blob/bedbe69/packages/tinfoil/src/config.ts#L13), [guest EHBP termination](https://github.com/tinfoilsh/cvmimage/blob/6389a774ba2d08131075279c7c8bc18b0f08a16c/tinfoil/cmd/shim/api.go#L196-L273)). The router decrypts requests itself, on a network declared `egress: open` in its measured configuration ([tinfoil-config.yml L86–88](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/tinfoil-config.yml#L86-L88)). It admits backends from evidence fetched without a nonce, and checks only the CPU report and code measurement: no GPU evidence, freshness witness or per-request appraisal. [Fetch](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/manager/manager.go#L240-L262), [verification](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/manager/manager.go#L300-L326). |
| `gpt-oss-120b` | Also runs its engine with an egress allowlist network. [v0.0.28 configuration](https://github.com/tinfoilsh/confidential-gpt-oss-120b/blob/v0.0.28/tinfoil-config.yml#L6-L9). |
| `kimi-k3` | Also loads model-supplied code with `--trust-remote-code`. [v0.0.10 configuration](https://github.com/tinfoilsh/confidential-kimi-k3/blob/v0.0.10/tinfoil-config.yml#L60). |

The runtime profile [rejects both configurations](../tools/tinfoil-public-build/runtime_test.go) even if their workers become reachable.

These router gaps matter against a malicious or compromised host or operator rather than in honest operation: without GPU evidence the router would not notice a GPU attached outside confidential mode, without firmware floors it accepts machines missing hypervisor-isolation fixes, and without a fresh nonce or per-request checks it keeps using a worker after the evidence it saw. The SDK-policy `router` route accepts those assumptions explicitly; public builds do not.

Direct worker access is not a configuration Tinfoil documents for its model workers. Its SDK and proxy pin a single enclave only as a documented mechanism for the router and for customers' own containers ([SDK option](https://github.com/tinfoilsh/tinfoil-js/blob/bedbe69/packages/tinfoil/src/secure-client.ts#L44-L51), [proxy](https://docs.tinfoil.sh/local-proxy/cli.md), [containers](https://docs.tinfoil.sh/containers/connecting.md)), and worker hostnames come from router status data. Tinfoil already restricts some workers' ingress to allowlisted addresses, so it could close direct access to the admitted models too; the profile then fails closed with no router fallback. Workers for admitted models that their platform publisher does not endorse, such as `glm-5-3-inf20` on 2026-10-07, are rejected and skipped; the router's live backend list still includes it. Gemma's AMD Genoa workers are rejected because their firmware lacks AMD's latest SEV-SNP fixes, so Gemma is served only by its TDX workers.

The next model worth unlocking is GLM-5.3 Flash: it scores within 7% of GLM-5.3 on the [Artificial Analysis Intelligence Index](https://artificialanalysis.ai/models/glm-5-3-flash) (41.8 against 44.8) at roughly a quarter of Tinfoil's per-task cost, and accepts images. Its signed v0.0.8 configuration already passes the runtime profile; only Tinfoil's ingress allowlist keeps its workers from direct connections. Kimi K3, the strongest model with image input, also loads its repository's Python code with `--trust-remote-code`. That code is pinned in the verity model pack at a public Hugging Face commit, so it is no less verifiable than the weights, but it adds the model developer as an author of code running beside plaintext; the profile currently rejects it.

No other confidential-inference provider qualifies either: a [survey of 30-odd providers](provider-survey.md) on 2026-10-08 found each fails at least one requirement only the provider can fix. The nearest misses are Privatemode (in-guest-only GPU verification, unsigned release manifest) and Confidential AI (operator cluster-admin access, which it plans to remove).

A router can be admitted later only if its measured code enforces the chosen public publisher/freshness/hardware policy on each actual downstream request, including sidecars and fallback. Polling a status endpoint before dispatch is insufficient. Backend updates within named public identities can be acceptable, but the client must know the enforced downstream contract. [Router update logic](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/manager/manager.go#L929), [conditional sidecar](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/safeguards/capture.go#L44).

NEAR's SDK routes are implemented; its public-build profile cannot qualify. A root-equivalent compose-manager deploys each worker's serving software at operator-chosen Git refs, with no release signature. That software can use the instance's TLS key and the app-wide KMS signing keys. A client can authenticate past deployments but cannot bound the next one. Chutes-backed models pass through NEAR's plaintext gateway. [NEAR assessment](nearai-status.md). The experimental direct route appraises GPU evidence with the local NVIDIA verifier and GPU policy Tinfoil uses, instead of NRAS. NEAR's eight Hopper GPUs run in PPCIe mode, which that policy does not admit, so the route fails closed until a policy for that hardware is decided. [Direct route](direct-access.md#near-direct-route-and-evidence).

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

The [closed serving contract](tinfoil-public-profile.md) records the public publisher, manufacturer, key/runtime and operator assumptions. The owned public-build session now connects that chain to the send-once worker transport, with authority/artifact digests and short-lived expiry checked again after payload hooks. An earlier single-model macOS ARM64 profile, its native local setup and the route wiring received independent implementation review. [Session review](reviews/pi-tee-public-session-opus-review.md), [setup review](reviews/pi-tee-local-setup-opus-review.md), [enablement review](reviews/pi-tee-enablement-opus-review.md). The actual-Pi `--public-builds` harness loads the production extension with default `auto` routing; `--public-builds-candidate` remains an isolated adapter test. NEAR [cannot qualify without server changes](nearai-status.md). Independent reviews of the WebAssembly verifiers, the NVIDIA reference-manifest patch, the TLS client and the multi-model/SEV-SNP generalization, and re-reviews of their fixes, preceded enabling the profile.

Availability, truthful billing, output correctness, traffic analysis, undocumented physical/side-channel protection and compromise of the user's local machine are outside the claim. Public-source monitoring and independent rebuilds can detect problems, but are not required to authorize each normal release. A frozen user manifest can impose that stricter policy later without making the extension maintain vendor deployment pins.

Written by Codex and Claude.
