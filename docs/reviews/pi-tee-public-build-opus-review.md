# Opus 5.5 review: public-build policy and `direct-public` candidate at `205b1af`

Reviewed fixed commit [`205b1af`](https://github.com/ariofrio/pi-tee/commit/205b1af3475b729a2587fca5a2b344b08c2ae687), extracted read-only to `work/opus-review-205b1af`. The follow-up [`718f385`](https://github.com/ariofrio/pi-tee/commit/718f3852b766d41b42327152cceedbe84458a35a) (TypeScript RTMR1/RTMR2 recomputation) needs its own review. I only checked whether F1 still applies to it.

Trust model applied: the named source, workflow and release maintainers, together with GitHub-hosted build and Sigstore authorities, are trusted to publish safe software and correct measurements. An authorized malicious release is accepted risk. Independent rebuilds and per-release source approval are optional. The client must still establish the hardware, GPU, key and serving-path requirements.

## Summary

- **No high-severity bug found.** Every value the client cannot verify for itself ultimately rests on a named, trusted authority, and transport is send-once with the TLS key pinned to the attested SPKI.
- **Main gap (F1).** The boot-register recomputation and the runtime/OCI checks run against the deployment file. The CPU quote is validated against the Sigstore predicate. The helper never checks that the two agree. Today the agreement holds only because the publisher made it so; the docs describe a binding to the running quote. This is cheap to fix on the client, and it is still open in `718f385`.
- **Policy inconsistency (F2).** `direct-public` still hard-codes the GPU driver and VBIOS versions. That is a deployment pin under a policy that promises automatic updates.
- **Under-specified gates.** Most of the remaining "qualification" in the docs (key, channel, reset, logging, egress) depends on contracts from the trusted publisher or NVIDIA. Those need to be recorded with source evidence, not tested experimentally. The finite gate list is below.

## Findings

| # | Severity | Category | Finding |
| --- | --- | --- | --- |
| F1 | Medium | Binding / claim exceeds evidence | Recomputed boot registers, cmdline, config, guest root and OCI root are checked against the **deployment subject**; the quote is validated against the **statement predicate**; nothing requires them to be equal. The two sides also select collateral differently. |
| F2 | Medium | Policy consistency | GPU driver `595.71.05` and VBIOS `96.00.D9.00.02` are fixed even in `public-builds` mode. |
| F3 | Medium | Test coverage | No offline negative tests at the Node chain boundary (`verifyPublicBuildArtifacts`). Only the Go subcommands and a live happy path are tested. |
| F4 | Medium (availability) | Operational | Every request downloads immutable artifacts again (2 unauthenticated GitHub API calls, up to 64 MiB of kernel/initrd, up to 100 helper runs). This collides with rate limits, and the re-download adds no security. |
| F5 | Low | Fragility | Local TDX floors reach `Assemble` only through pointer aliasing inside tinfoil-go, and no test covers this. |
| F6 | Low | Missing cheap check | The platform-endorsement and freshness certificates are not required to have public visibility or `BuildSignerDigest == SourceRepositoryDigest`, unlike the workload and CVM certificates. |
| F7 | Low | Parser differential | Go decodes the deployment and OCI JSON with lenient `encoding/json` (case-insensitive keys, last duplicate wins); Node uses `JSON.parse`. |
| F8 | Low | Local TOCTOU | The helper is hashed once, then executed by path up to ~100+ times over as long as 240 s. |
| F9 | Info | Response integrity | EHBP frames carry no authenticated end-of-stream marker. Clean EOF at a frame boundary relies on TLS framing pinned to the attested key. |

### F1 — The verified artifacts are not bound to the measurement the CPU quote was checked against

**Evidence**
- Go `verify()` validates the quote's RTMR1/RTMR2 against `code.Measurement`, which comes from the signed **predicate** ([main.go#L146](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/main.go#L146); [provenance.go `measurementFromStatement`](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/provenance/provenance.go#L337)). Its result contains no registers ([main.go#L38-L53](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/main.go#L38-L53)).
- Node compares the recomputed RTMR2 with `deployment.tdx_measurement.rtmr2`, a field of the downloaded **subject** bytes ([public-build.ts#L85](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/packages/tinfoil/src/public-build.ts#L85)). In `718f385`, RTMR1 and RTMR2 are both compared with `deployment.tdx_measurement.*`, and RTMR1 uses `deployment.vm_shape.memory_mb` (subject).
- `--runtime-config` and `--container-reference` read `config`, `cmdline` and `hashes` from the subject with `json.Unmarshal` ([runtime.go#L348-L372](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/runtime.go#L348-L372), [container.go#L79-L85](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/container.go#L79-L85)). Only the VM shape comes from the predicate ([runtime.go#L367](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/runtime.go#L367)).
- Collateral selection differs:
  - Go takes the **first** `reference-values` entry with the sigstore-code format, whatever its ID ([envelope.go#L530-L541](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/envelope/envelope.go#L530-L541)).
  - Node takes the entry whose `id === "code"`, whatever its role or format ([public-build.ts#L90-L92](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/packages/tinfoil/src/public-build.ts#L90-L92)).
  - Collateral is not covered by REPORT_DATA. The provider controls the list, so it can supply two different signed bundles. Both must still authenticate the same digest, tag and commit (asserted at L94-L96).
- Observation: in the v0.0.25 fixtures, the predicate equals the deployment JSON field for field ([testdata/gemma-v0.0.25.bundle.json](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/testdata/gemma-v0.0.25.bundle.json), [deployment](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/testdata/gemma-v0.0.25-deployment.json)). The code does not require that.

**Impact under the trust model.** Only the trusted publisher can produce a mismatch: a predicate that differs from the subject, or two signed statements for one release. Confidentiality therefore still rests on the trusted publisher, but the runtime-profile constraints, model-pack roots, OCI root and "RTMR recomputed" claims are not tied to the code the quote attests. The [tools README](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/README.md#L44) and [design.md](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/docs/design.md#L63) claim more than the code establishes.

**Correction**
1. In Go, when authenticating the code bundle, strictly decode the subject deployment JSON. Require `snp_measurement`, `tdx_measurement`, `vm_shape`, `cmdline`, `hashes` and `config` to equal the predicate exactly, with no extra fields.
2. Have the main CPU `verify` emit the quote-authenticated RTMR1, RTMR2 and `vm_shape`. Node should compare its recomputation with those values, not with `deployment.*`.
3. Bind the bundle identity across subcommands: either pass the whole envelope and let Go select collateral once, or emit the authenticated bundle's statement digest from `verify` and require each later subcommand result to match it.
4. Add a real-artifact negative test: the authentic deployment with `tdx_measurement.rtmr2` changed must be rejected even when it is supplied as subject bytes.

### F2 — Frozen GPU versions in `public-builds` mode

[intel-appraisal.ts#L79-L81](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/packages/tinfoil/src/intel-appraisal.ts#L79-L81) requires exactly driver `595.71.05` and VBIOS `96.00.D9.00.02` on both routes. The guest builds the driver into a CVM release, so the first authentic CVM release with a new driver fails closed until the extension is updated. That contradicts "a new release does not require updating deployment hashes in the extension" ([design.md#L9](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/docs/design.md#L7)).

The failure mode is availability, not confidentiality: the check fails closed.

**Correction.** In `public-builds` mode, keep everything except the version pins:
- the NVIDIA signature, nonce and chain checks;
- driver/VBIOS RIM signature, version match and measurement match;
- three good OCSP responses;
- debug and secure-boot status;
- opaque-data version 1 and SPT.

Replace the exact versions with explicit local minimum floors. Optionally also require the driver version to equal the one declared by the authenticated guest build's source ([nvidia-modules.nix](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/nix/nvidia-modules.nix)). Keep the pins for `direct-intel`.

### F3 — Node chain negatives are missing

The Go negatives are good: CVM, container and runtime substitution tests with real signatures. They passed offline in my run (`go test ./...` → ok). The live CPU test is skipped without the private fixture.

[tests/tinfoil-intel.test.ts](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tests/tinfoil-intel.test.ts) covers only the helper pin and send-once. Nothing exercises the Node-only checks:
- deployment digest;
- source-config equality;
- exact cmdline;
- CVM candidate selection;
- kernel/initrd digest;
- RTMR comparison;
- OCI index ambiguity;
- GitHub parent and Dockerfile checks;
- the outer `catch` mapping.

**Correction.** Use the existing `evidenceFetch` seam with the public fixture bytes and the real helper. Gate the CPU-dependent step on the existing optional private fixture, as `718f385` reportedly does for its RTMR tests. Add one mutation per Node check, and assert zero GPU or inference requests after each rejection.

### F4 — Per-request download of immutable artifacts

[public-build.ts#L44-L141](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/packages/tinfoil/src/public-build.ts#L44-L141) runs on every Pi request:
- 2 `api.github.com` calls. Unauthenticated, the limit is 60 per hour per IP, so at most about 30 requests per hour.
- 2 kernel/initrd downloads, up to 32 MiB each.
- GHCR token, manifest and blob fetches.
- raw.githubusercontent.com fetches.
- up to 100 `--cvm-build` helper runs.

Every one of these artifacts is addressed by digest or commit. Caching them, and the deterministic helper results keyed by input digest, changes no security property. The quote, GPU report, freshness witnesses and nonce must stay per request.

**Correction.** Add an owner-only, digest-keyed cache for these artifacts and helper results. Never cache freshness, CPU or GPU results.

### F5 — Local floors rely on aliasing

[main.go#L130-L146](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/main.go#L130-L146) mutates `cpu.TDX`, then calls `quote.Assemble(platform.Artifact, …)`, which looks the policy up again. This works at 23734b7 only because [`PolicyFor`](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/policy/artifact.go#L143-L153) copies the `Policy` struct but shares the `*TDXPolicy` pointer. If a dependency update deep-copies, the TEE_TCB_SVN and collateral-edition-20 floors are silently dropped, and no test fails.

**Correction.** Build an explicit floored copy of the artifact before `Assemble`. Add a unit test proving that a synthetic below-floor policy is raised in the copy passed to `Assemble`. A forged quote is not needed for this test.

### F6 — Missing certificate checks for platform and freshness

[`requireCodeWorkflow`](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/main.go#L57-L81) and [cvm.go#L98-L103](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/cvm.go#L98-L103) require public visibility at signing and `BuildSignerDigest == SourceRepositoryDigest`. The platform-endorsement and freshness certificates are checked only against tinfoil-go's SAN regex and `github-hosted` ([provenance.go#L46-L47](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/provenance/provenance.go#L46-L47)).

The SDK's tag pattern for platform endorsements, `v[0-9][^@]*`, is broader than the local `stableTag`. The local check runs only on the envelope's claimed tag, but `authenticatedArtifact` requires the certificate tag to equal that claimed tag, so the combination is sound.

Under the trust model the named identity is sufficient. The auditability claim depends on those repositories staying public, though, and the check costs nothing.

**Correction.** Apply the same certificate-extension checks to both certificates, including `SourceRepositoryURI` and ref.

### F7 — Lenient JSON decoding

[container.go#L82](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/container.go#L82), [#L116](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/container.go#L116) and [runtime.go#L356](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/runtime.go#L356) accept duplicate and case-variant keys. Node cross-checks `configDigest`, `cmdline` equality and the image digest, so most divergence fails closed. Fields checked on only one side, such as Go's `hashes.root` and Node's `cvm.hashes.root`, can still diverge.

Only the publisher can sign such bytes. The YAML path is already strict (duplicate, alias and merge rejection plus `KnownFields`).

**Correction.** Use strict decoding (duplicates rejected, case-sensitive, unknown fields rejected) for the deployment and OCI documents. Prefer Node consuming Go-emitted values over re-parsing.

### F8 — Hash-then-execute

[intel-appraisal.ts#L52](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/packages/tinfoil/src/intel-appraisal.ts#L52) hashes the helper; [public-build.ts#L26](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/packages/tinfoil/src/public-build.ts#L26) later executes the path repeatedly. The NVAT directory is likewise hashed, then bind-mounted. The local machine is trusted, so this is defense in depth only.

**Correction.** Copy the helper to an owner-only private directory and execute the copy. Alternatively, re-hash before each execution.

### F9 — No authenticated end-of-stream

[ehbp 0.3.3 `createDecryptStream`](https://github.com/tinfoilsh/encrypted-http-body-protocol) closes cleanly at any frame boundary. A network truncation must defeat TLS pinned to the attested key and HTTP framing. Node surfaces a premature close as an error, so the residual risk is truncation by the attested endpoint itself, which falls under output correctness.

No change is required. Optionally, require a terminal `finish_reason` or `[DONE]` before exposing tool calls.

## Claims versus evidence

| Claim | Status |
| --- | --- |
| "Requires UpToDate appraisal, revocation and valid collateral" ([design.md#L59](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/docs/design.md#L61)) | **Supported.** [go-tdx-guest `checkTcbInfoTcbStatus`](https://github.com/google/go-tdx-guest/blob/v0.3.1/verify/verify.go#L940) rejects non-UpToDate TDX module, platform TCB and QE. tinfoil-go sets `CheckRevocations: true` and adds a CRL `ThisUpdate` check ([authenticate.go#L99](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/quote/tdx/authenticate.go#L99), [#L181](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/quote/tdx/authenticate.go#L181)). Exact TD attributes `0000001000000000` exclude debug and migratable. |
| "Applies local TDX floors" | **True at 23734b7; untested** (F5). |
| "Recomputes RTMR2" (and RTMR1 in `718f385`) as a boot-chain check | **Overstated.** It matches the deployment subject, not the quote (F1). |
| "CPU-bound GPU evidence" | **Supported.** `device_evidence` is hashed into REPORT_DATA ([envelope.go `Check`](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/envelope/envelope.go)). The JS reads the identical, strictly pre-validated bytes; strictjson rejects duplicates and case variants, so JS/Go parser divergence is excluded. The GPU nonce equals the client nonce, and NVIDIA confirms it. |
| runtime.go "same … semantics used by the measured Go guest" ([runtime.go#L89-L90](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/tools/tinfoil-public-build/runtime.go#L89-L90)) | **Imprecise.** The verifier is a stricter subset. The guest treats a string `env` entry as a lookup in the operator's external config ([containers.go#L661-L690](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/containers/containers.go#L661-L690)). The verifier's `[]map[string]string` type rejects that form, which is the right result. Reword the comment and add a test that rejects a string env entry. |
| Mode: "Python interpretation" chosen | **Supported by source.** [nvtrust 858ada9](https://github.com/NVIDIA/nvtrust/blob/858ada9a17f58c482f578414ea2455498fa51e17/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/attestation/spdm_msrt_resp_msg.py#L365) maps 0→SPT; the [C++ enum](https://github.com/NVIDIA/attestation-sdk/blob/9d12801cea8a198ea0f29640dfaf8a4017c841c5/nv-attestation-sdk-cpp/include/nv_attestation/gpu/evidence.h#L98) is reversed, and [claims.cpp#L193-L195](https://github.com/NVIDIA/attestation-sdk/blob/9d12801cea8a198ea0f29640dfaf8a4017c841c5/nv-attestation-sdk-cpp/src/gpu/claims.cpp#L193-L195) has the mode serializer commented out. The repo's own compatibility-matrix observation (SKU 280 rows list only SPT and PPCIe) also argues against reading 0 as MPT; the doc could say so. Caveat: the cited C++ source is not proven to be the shipped NVAT 1.2.2 binary. That does not matter here, because the mode is parsed client-side and signature coverage of the field was tested (result `508`). |
| "Driver rejects non-CC GPU", "fatal state irreversible" | **Citations accurate** ([conf_compute.c#L137](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/51edebee79919b54f498c19a0be31982cd97646e/src/nvidia/src/kernel/gpu/conf_compute/conf_compute.c#L137), [conf_compute_api.c#L185](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/51edebee79919b54f498c19a0be31982cd97646e/src/nvidia/src/kernel/gpu/conf_compute/conf_compute_api.c#L185)). The driver also accepts a protected-PCIe GPU, so the client-side SPT requirement is load-bearing. |
| Helper pin `dae400da…` corresponds to the commit's source | **Observed.** I rebuilt from the `205b1af` snapshot offline (`GOTOOLCHAIN=go1.26.6 -trimpath -buildvcs=false`) and got exactly `dae400da525dc621f55aa6f6825726e8d67dfdf4cc770e5b1958f0b2a74cc37e`. |
| OCI BuildKit metadata is publisher-endorsed, not an independent builder receipt | **Accurately disclosed** (`independentBuilderVerified: false`). |

## Key, runtime, GPU and reset evidence by category

**Manufacturer contracts** (documented, not tested here):
- Intel: TDX module isolation and the PCS/TCB/revocation processes.
- NVIDIA: SPDM session keys, CPU–GPU bounce-buffer encryption, scrubbing on reset ([WP-12554-001 v1.3 pp. 11–13](https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf)); devtools GPUs fail RIM matching ([R595 notes p. 10](https://docs.nvidia.com/595trd1-trusted-computing-solutions-release-notes.pdf)); the attestation report is retrieved from the same device the driver's SPDM session authenticated.

These are trust declarations. A client cannot verify them beyond signed evidence.

**Software contracts of the trusted publisher**, with source evidence at cvmimage [`a4dbce0`](https://github.com/tinfoilsh/cvmimage/tree/a4dbce07f5b0efbee1df678026db538eba66a613):

- **Keys**
  - TLS P-384 and HPKE keys are generated in the guest ([identity.go#L26-L60](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/boot/identity.go#L26)).
  - They are stored under the RAM-disk private directory `/mnt/ramdisk/private`, mode 0700, readable by boot, egress and shim, and never mounted into containers ([paths.go#L3-L21](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/boot/paths.go#L3-L21)).
  - The HPKE "load-or-create" therefore persists only within one boot.
  - Root-capable guest processes (PID 1, dockerd, nvidia-persistenced) remain inside the trusted publisher software.
- **Egress and routing**
  - With no configured networks, the engine container joins only the shim network ([containers.go#L366-L391](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/containers/containers.go#L366-L391)). The firewall writes that network as `egress=closed` ([firewall/containers.go#L27](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/firewall/containers.go#L27), [#L45](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/firewall/containers.go#L45)).
  - The shim's upstream is the fixed `172.31.255.2`, with no DNS lookup ([upstream.go#L7-L9](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/shim/upstream.go#L7-L9); parent finding, confirmed).
  - The profile rejects `networks`, so engine egress is closed by construction.
- **Logging and console**
  - The production kernel fragments set `NULL_TTY` as the default console and disable virtio/8250/earlycon ([20-production-console.config](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/kernel/config.d/20-production-console.config), [20-console-common.config](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/kernel/config.d/20-console-common.config)). I confirmed the fragments exist; I did not re-trace which fragments the release build applies.
  - The profile rejects vLLM request-logging flags.
- **Container and model inputs**
  - Read-only root by default ([containers.go#L476](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/containers/containers.go#L476)) and `CapDrop ALL`.
  - Model packs are mounted through dm-verity with a salt derived from the measured repo/revision ([models.go](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/boot/models.go)).
  - Encrypted model packs (`emwp`), which take keys from the operator's external config, are excluded by the profile's typed decode.
- **GPU lifecycle**
  - `modules_disabled=1` prevents loading **and unloading** modules ([module_lock.go](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/pid1/hardening/module_lock.go)), so the driver cannot be reloaded to clear its fatal state.
  - With the fatal-state code above, a host reset of the GPU after attestation should cause driver failure, not unprotected serving. That conclusion is manufacturer plus software contract, not an observation.

**Operator inputs not covered by any measurement.** The external config (`env`, `secrets`, `network`, `vault-token`, metadata) is untrusted. Under the profile it can only affect:
- the network address;
- the ACME DNS tokens, which matter little because clients pin the attested SPKI rather than WebPKI;
- registry credentials, which affect only availability because the image is pinned by digest;
- the metrics bearer key.

This list should appear verbatim in the recipient inventory.

**Actual test observations**
- Live CPU quote UpToDate under the local floors.
- Live NVIDIA local appraisal (signature, nonce, RIMs, OCSP, SPT value `0`) with negatives for a forged signature, wrong nonce and mode-field substitution (`508`).
- Full actual Pi suite and live-delta cancellation, as reported by the implementer.
- Go offline real-signature substitution tests (rerun by me: pass).
- Helper hash reproduced (by me).
- RTMR recomputation equal to the deployment fields.

**Not observed, and not required as experiments:** a genuinely signed non-SPT GPU, GPU reset during service, side channels. The first two are covered by manufacturer contracts plus the signed-field coverage test.

## Finite list of necessary remaining production gates (accepted trust model)

The gates below are the complete list. Items marked *software contract* need written source evidence and review, not a hardware experiment.

1. **Bind the artifacts to the quote (F1).** Strict predicate–subject equality, quote-derived RTMR/shape values in the Node comparison, and a single bundle selection. *Client code.*
2. **Remove version pins from the `public-builds` GPU policy (F2).** RIM, OCSP and nonce/SPT checks plus local minimum floors. *Client code.*
3. **Close the Node-chain test gap (F3)** and the F5 floor test. *Client tests.*
4. **Wire production admission.** Make `public-builds` call the `direct-public` chain instead of throwing `TEE_PUBLIC_BUILD_DEPLOYMENT_UNAVAILABLE` ([provider.ts#L126](https://github.com/ariofrio/pi-tee/blob/205b1af3475b729a2587fca5a2b344b08c2ae687/packages/core/src/provider.ts#L126)). Return the owned session described in design.md: model, authority-policy digest, release digests, keys, freshness. Keep send-once. *Client code.*
5. **Record the closed trust and recipient inventory for this profile in SECURITY/design.**
   - Remote authorities: Intel; NVIDIA (device CA, RIM CA, RIM service, OCSP); the Sigstore root `6494e21e…`; GitHub OIDC and hosted runners; the four Tinfoil publisher identities; GitHub public-source delivery (audit check only).
   - Plaintext and key recipients: the attested CVM only, namely shim and engine.
   - Operator capabilities from the external-config list above.
   - Local stack: Pi, Node, helper `dae400da…`, NVAT 1.2.2, Docker image `b67dad12…`.

   *Documentation of the trust model; no experiment.*
6. **Write down the software and manufacturer contracts above as the profile's key, channel and reset basis**, with the pinned source links. State explicitly that they are trusted contracts, re-established for each release only through the publisher's identity. *Documentation.*
7. **Availability engineering (F4).** A digest-keyed artifact cache and a supported, packaged local verifier set beyond macOS ARM64 + Docker. This is required for usable production, not for confidentiality.
8. **Review gate (CONTRIBUTING).** An independent review of the final combined verifier and transport, covering `718f385` and the fixes for gates 1–4.

The following are **not** necessary under the accepted trust model:
- an independent rebuild of guest, engine or models;
- per-release source review;
- model-weight attribution to Google's Hugging Face revision (dm-verity roots are publisher-measured);
- a live signed non-SPT GPU or a physical reset experiment;
- a second live deployment test. Replace it with an offline replay of the guest-build chain across authentic releases, which already exists for CVM v0.11.0/v0.14.13, plus gate 2.

The whole-session Pi guard (`protectedSession`) remains a separate claim and does not gate per-dispatch admission.

## NEAR: what a client can and cannot solve

Evidence: the NEAR SDK at [`b993089`](https://github.com/nearai/inference-sdk/tree/b9930893a9f560e66898e1616111c5ac2241686c). REPORT_DATA is `SHA-256(signing address ‖ TLS SPKI) ‖ nonce` ([attestation-common.ts#L57-L61](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/core/attestation-common.ts#L57-L61)). The SDK already replays RTMR3 and binds `app_compose` to `mrConfigId` ([event-log.ts#L33](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/core/event-log.ts#L33), [attestation-common.ts#L188-L211](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/core/attestation-common.ts#L188-L211)).

**Client-solvable**
- Appraise MRTD/RTMR0–2 locally, against measurements computed from public dstack OS-image artifacts, instead of trusting the guest-written OS hash.
- Apply static constraints to the bound `app_compose`, analogous to the Tinfoil runtime profile (digest-pinned images, no privileged mounts).
- Use local NVIDIA appraisal instead of NRAS JWT verdicts, as the Tinfoil route already does.
- Compute the client's own TLS exporter (`tlsSocket.exportKeyingMaterial`) so the client side of an RFC 9266-style binding is ready.

**Not client-solvable** (server changes required)
- **CPU–GPU association.** No device-evidence hash in REPORT_DATA; the GPU nonce equality proves freshness only.
- **Instance/session binding** against the shared TLS and signing keys. A measured terminator must quote its own exporter.
- **Key release and KMS behavior** and runtime mutation. These need published deployed-KMS/governance evidence, though a client could verify that evidence if it were published.
- **Package and model downloads inside containers at runtime.**

## Verification performed

- `git archive 205b1af` into a read-only snapshot. No repository edits, no inference, no external messages, no secret or raw private-quote access.
- Offline `go test ./...` in `tools/tinfoil-public-build`: pass. The live CPU test is skipped without the fixture.
- Offline helper rebuild: hash `dae400da…` matches the pin.
- Source reads at pinned revisions: tinfoil-go `23734b7` (module cache), go-tdx-guest `v0.3.1`, cvmimage `a4dbce0`, nvtrust `858ada9`, attestation-sdk `9d12801`, open-gpu-kernel-modules `51edebe`, NEAR SDK `b993089`.
- `718f385` inspected only for F1 (still present in its `public-build.ts`). It requires its own review.

Written by Claude Opus 5.5.
