# Tinfoil release drift, 2026-11-07

Observed 2026-11-07 21:55–22:40 UTC from macOS on Node 26.10, client 852279d and this branch, policy `trust-provider-and-host`. Every Tinfoil route rejected `deepseek-v4-1-flash`, and the router rejected `kimi-k3-1-pro`. Other public models were checked for the same causes.

## Observations

| Route at 852279d | Reported | Helper or check that failed | Evidence presented |
| --- | --- | --- | --- |
| `tinfoil-router` | `TEE_PUBLIC_BUILD_REJECTED` | `--router`: `TEE_PUBLIC_BUILD_BINDING_REJECTED` in [`codePredicate()`](../../../tools/tinfoil-public-build/release.go) | `confidential-model-router` v0.0.171 on SEV-SNP; its signed predicate carries an unknown `firmware` member naming `tinfoilsh/edk2` v0.0.4 `OVMF.fd` |
| `tinfoil-direct` | `TEE_WORKER_DISCOVERY_UNAVAILABLE` | [Discovery](../../../packages/tinfoil/src/worker-discovery.ts) tag check | Both delivery documents list DeepSeek at tag `v0.0.10+b200` |
| `tinfoil-gateway` | `TEE_PUBLIC_BUILD_REJECTED` | Default mode: `TEE_PUBLIC_BUILD_IDENTITY_REJECTED` in [`requireReleaseWorkflow()`](../../../tools/tinfoil-public-build/main.go) | `deepseek-v4-1-flash-inf16-0` on TDX; certificate identity `tinfoil-release-publish.yml@refs/tags/v0.0.10+b200`, GitHub-hosted, public source |

- Tinfoil's release action added the `firmware` member in [measure-image-action v0.13.0](https://github.com/tinfoilsh/measure-image-action/releases/tag/v0.13.0) (2026-09-16). Router releases carry it from [v0.0.156](https://github.com/tinfoilsh/confidential-model-router/releases/tag/v0.0.156) (2026-10-12); every current Gemma, DeepSeek and GLM release carries it too. Tinfoil's verifier reads only the measurement and shape members.
- DeepSeek releases use SemVer build-metadata tags from [v0.0.5+b200](https://github.com/tinfoilsh/confidential-deepseek-v4-1-flash/releases/tag/v0.0.5%2Bb200) (2026-10-16) onward, one per GPU variant; v0.0.4 was the last plain tag. GitHub marks them as full releases, and their certificates match the existing workflow identity apart from the tag. Tinfoil's verifier accepts any tag.

## After decoding the firmware member and admitting build-metadata tags

The router passes and serves both models. Direct and gateway still reject every current public release, at later checks:

- **Runtime profile.** [`inspectRuntimeConfig()`](../../../tools/tinfoil-public-build/runtime.go) rejects Gemma v0.0.30, GLM-5.3 v0.0.10 and both DeepSeek v0.0.10 variants with `TEE_RUNTIME_CONFIG_REJECTED`. All four configurations use container fields, environment variables, flags or flag values outside `tinfoil-vllm-v1`. Examples: DeepSeek b200 sets 17 unlisted environment variables, `PYTORCH_CUDA_ALLOC_CONF=expandable_segments:False`, a third tmpfs mount, `--kv-cache-dtype fp8_ds_mla` and `--cudagraph-metrics`; GLM-5.3 sets `shm_size`, `--kv-offloading-backend`, `--kv-transfer-config` and `--hf-overrides`; Gemma sets per-container `memory`, `models` and `shm_size`, `--seed` and `--trust-request-mm-kwargs`. The profile was qualified against Gemma v0.0.25 (2026-08-12) and DeepSeek v0.0.3.
- **SEV-SNP firmware.** The releases' SEV-SNP launch measurements were computed with `tinfoilsh/edk2` v0.0.4 `OVMF.fd`, SHA256 `78c890175928167a1bc095d4bf3bb4ad81de80cd7e4e9e683477fc359119c1c4`. pi-tee pins v0.0.3. For GLM-5.3 v0.0.10 (guest v0.14.17, 32 vCPUs), `sev-snp-measure` 0.0.12 reproduces the signed `acf16e1d…` only with v0.0.4; v0.0.3 and pi-tee's calculator both give `3dfb9366…`. SEV-SNP workers would fail boot-measurement recomputation even with an admitted runtime.

Admitting either change widens what pi-tee accepts, so neither is applied here: the runtime profile needs per-setting review, and the firmware pin needs authenticated v0.0.4 measurement constants. TDX workers are unaffected by the firmware pin.
