# Tinfoil workload qualification

The Intel direct candidate has working local CPU/GPU appraisal and an attested encrypted transport. Qualification is unfinished, rather than blocked on credentials or provider permission. This page separates checked source properties from remaining production hardware/serving-path qualification. Its fixed artifacts are research fixtures; the [normal public-build policy](design.md) accepts updates from named public release/build authorities rather than requiring independent approval of each release. [Hardware policy and local artifacts](intel-candidate.md), [security contract](../SECURITY.md).

## Boot-artifact trace

The pinned deployment contains the exact [Gemma configuration](https://github.com/tinfoilsh/confidential-gemma4-31b/blob/43dc8f6d1c4d9c1504559ab181cf9dfe00ad239b/tinfoil-config.yml). Its command line binds configuration SHA256 `1aeed2c83d17555fcffbf1f6ec82f0cefd22ea09d61b4b1385b5d1451ed706a4` and guest dm-verity root `6bf30dfe78f9646111afbc718e3a819d618981f453f31ecca8d4e166b9fc9dd9`.

On 2026-10-07, downloaded kernel/initrd bytes matched their pinned SHA256 values. GitHub CLI verified their build provenance with an exact source commit, tag, signer digest and workflow identity, rejecting self-hosted runners. Both selected the [v0.11.0 release build](https://github.com/tinfoilsh/cvmimage/actions/runs/31558890695/attempts/1). The [public-build probe](../tools/tinfoil-public-build/README.md) now performs that guest-chain verification locally against an embedded Sigstore root set, deriving the version from the authenticated deployment instead of a built-in pin. It verifies the manifest/kernel/initrd/disk subjects in one build statement, checks downloaded kernel/initrd bytes and recomputes RTMR2. This uses GitHub/Sigstore build-identity authorities for artifact attribution; it does not approve source behavior or independently rebuild the disk. [Live metadata](public-build-evidence.json).

A local locked build of [tdx-measure v0.0.6](https://github.com/tinfoilsh/tdx-measure/tree/9311cb9bdf3f83c9e3ec8dae4b6dff78a6d46123) recomputed both RTMR1 and RTMR2; both matched the deployment and local CPU policy. The calculation used the release producer's [runtime-only invocation](https://github.com/tinfoilsh/measure-image-action/blob/ca4cfa35773897455c9e51409d61c75b8e377c27/measure_intel.py), including its `65536G` memory argument. This reproduces its measurement calculation, not the platform's firmware/topology. [Recorded checks](tinfoil-workload-evidence.json).

The shipping-image derivation graph contains 2,410 derivations and 873 fixed outputs. The [input inventory](tinfoil-build-inputs.json) records their declared hashes and delivery URLs, plus the separately pinned evaluation-time Nixpkgs archive. Six fixed outputs are generated/vendor aggregates rather than direct URL fetches. This enumerates build inputs, not the final runtime process set or a successful independent image rebuild. Evaluation used the installed local Nix; it did not run or qualify the release's isolated Linux builder.

The dependency-free [boot check](../scripts/research/tinfoil-boot.mjs) separately recomputes RTMR2 from the UTF-16LE, NUL-terminated command line plus initrd. It passed with real artifacts and rejected separate one-byte mutations of deployment, configuration, kernel and initrd. It neither authenticates a CPU quote nor approves software. [Event calculation](https://github.com/tinfoilsh/tdx-measure/blob/9311cb9bdf3f83c9e3ec8dae4b6dff78a6d46123/src/kernel.rs#L121).

```sh
node scripts/research/tinfoil-boot.mjs ARTIFACT_DIRECTORY SOURCE_CONFIG
```

Use the exact [deployment JSON](https://github.com/tinfoilsh/confidential-gemma4-31b/releases/download/v0.0.25/tinfoil-deployment.json), `tinfoil-inference-v0.11.0.vmlinuz` and `tinfoil-inference-v0.11.0.initrd` in that directory. Their URLs are under `https://images.tinfoil.sh/cvm/`; the script enforces fixed digests, independently of delivery. The source config is the file at the linked commit.

## Runtime source checks

These observations apply to CVM commit `a4dbce07f5b0efbee1df678026db538eba66a613`. They support the audit; they do not establish that every runtime path is safe.

| Boundary | Checked source property | Remaining qualification |
| --- | --- | --- |
| Guest and configuration | [Initrd](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/initrd/main.go#L67) opens a fixed dm-verity root and mounts it read-only. [Boot](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/boot/config.go#L84) hashes configuration bytes against the measured command line. | Review firmware/measurement derivation, rootfs contents and source-to-binary evidence. |
| Runtime writers | The [container manager](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/containers/main.go#L68) opens its configuration-replacement socket only in debug mode. The fixed command line has no debug flag. [Module loading](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/pid1/hardening/module_lock.go#L15) is locked before general services start. | Complete the privileged-process, Docker socket, external-configuration and writable-filesystem inventory. |
| Keys | [Identity generation](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/boot/identity.go#L26) creates TLS/HPKE keys in the guest; [private paths](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/boot/paths.go#L16) are distinct from the public container mount. | Review each key reader/export path, logs, persistence and teardown. File permissions alone do not exclude privileged guest processes. |
| Engine and weights | [Container specification](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/containers/containers.go#L472) drops capabilities and defaults to read-only root. The [configuration](https://github.com/tinfoilsh/confidential-gemma4-31b/blob/43dc8f6d1c4d9c1504559ab181cf9dfe00ad239b/tinfoil-config.yml) selects a digest-pinned engine and two fixed model packs; [model mounting](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/boot/models.go#L83) enforces dm-verity. | Qualify engine dependencies, tokenizer/templates, code loading, logging, caches and egress. |
| GPU lifecycle | [Boot appraisal](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/boot/gpuattest.go#L190) enables ready state after verification. [Fresh evidence collection](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/attestation/gpu.go#L77) uses local NVML. [PID 1](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/pid1/main.go#L388) starts persistence services. | Establish strict CC mode and the exact driver's protected execution path across reset/restart; fresh file appraisal alone does not establish those properties. |

NVIDIA documents driver–GPU SPDM key establishment, encrypted single-GPU bounce buffers and state cleanup in [WP-12554-001 v1.3, pages 11–13](https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf). Its earlier [H100 paper, page 28](https://images.nvidia.com/aem-dam/en-zz/Solutions/data-center/HCC-Whitepaper-v1.0.pdf) explains persistence and reset/scrubbing requirements. These identify mechanisms to check in the pinned stack; neither document is proof of the worker's complete runtime behavior.

The [current GPU runtime assessment](tinfoil-gpu-runtime.md) records the live signed-mode field, a mismatch between NVIDIA's C++ and Python mode numbering, omitted C++ JSON mode output, exact driver SPDM/UVM/fatal-error paths and manufacturer devtools/compatibility evidence. The experimental Intel route now enforces the signed SPT field after NVIDIA verification; complete reset and execution-path qualification remains.

## Work still required

Finish the source/artifact and runtime checks above, apply any required enforcement changes, run adversarial tests at their real boundaries, then obtain the independent implementation/verifier/transport review required by [CONTRIBUTING.md](../CONTRIBUTING.md). The earlier Opus review covered the design. Neither these checks nor successful inference authorize a production profile by themselves.

NEAR needs a demonstrated instance/session binding that its shared keys currently do not provide. A measured terminator quoting its own TLS exporter is one proposed server change; quoting a client-supplied value would still permit relay. [NEAR evidence and protocol requirement](direct-access.md#near-direct-route-and-evidence).

Written by Codex.
