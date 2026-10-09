# Portable local verification

Local verification runs on every Pi platform with no setup. NVIDIA's verifier ships inside `pi-tee-core` and Tinfoil's CPU/release verifier inside `pi-tinfoil`, both as WebAssembly, and the inference transport uses only `node:tls`. There is no Docker, compiler, platform binary or download step. [Build recipe and runtime boundary](../tools/nvidia-verifier/README.md).

## Scope

Pi's [binary builds](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/scripts/build-binaries.sh) cover macOS, Linux and Windows on x64 and ARM64; its [Termux instructions](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/docs/termux.md) add Android under Node. Pi runs under npm/Node and as Bun-compiled binaries.

| Component | Implementation |
| --- | --- |
| CPU and release verifier | The Go public-build helper as a WASI command, under a minimal shim with no file system or network. |
| GPU verifier | NVIDIA's verifier with the [reference-manifest patch](../tools/nvidia-verifier/patches/rim-leaf-signature.patch), compiled with Emscripten. The patch binds the signer to the appraised certificate, requires NVIDIA's signature layout and reads manifest content only from signed locations. It fetches signed NVIDIA references and OCSP responses through a bridge restricted to NVIDIA's two services. |
| Inference transport | `node:tls` checks the attested SPKI on the socket, then writes one HTTP/1.1 request on that socket and reads the response. Bun's `https.Agent` cannot adopt an externally verified socket, so `node:https` is not used. |

The extension authenticates each module's SHA-256 before compiling it. Verifiers run in worker threads that are terminated on cancellation or timeout. The pinned hashes authenticate the client installation; they do not freeze Tinfoil's workload releases.

## Evidence

On 2026-10-07, the WebAssembly NVIDIA verifier returned the same 49 claims as the native build for fresh Hopper evidence; only the signed detached EAT differed. It rejected every collateral and evidence negative in the [check script](../scripts/check-nvidia-verifier.ts) with the expected NVIDIA code. The WASI CPU helper passed its Go test suite and the [artifact-chain tests](../tests/public-build-chain.test.ts), including every substituted delivery artifact. A full fresh CPU/GPU/release appraisal of a one-GPU worker took 3.8 s under Bun and 5.5 s under Node, mostly network. On 2026-10-08, eight-GPU workers took 7–13 s under Node: each GPU needs its own reference and OCSP requests. The same day, the verifier rebuilt with the hardened reference-manifest patch accepted fresh Hopper evidence and eight-GPU Blackwell evidence from the DeepSeek V4.1 Flash and GLM-5.3 workers, and rejected each layout negative with its expected code.

The experimental `direct-public` route passed the [actual Pi suite](../scripts/live-pi.ts) for Gemma 4 31B, DeepSeek V4.1 Flash and GLM-5.3 under the Node CLI and the official Bun-compiled Pi 1.0.4 macOS ARM64 binary: login, stored-key precedence, completion and usage, Unicode tools, reasoning, and cancellation, both at the consumption barrier and after a live text delta.

The [workflow](../.github/workflows/wasm-verifiers.yml) rebuilds the modules and compares them with the committed bytes. It also runs the WebAssembly, TLS and NVIDIA checks under Node and Bun on all six desktop targets; [run 37857229601](https://github.com/ariofrio/pi-tee/actions/runs/37857229601) passed every job, including the rebuild comparison.

## Limits

- Android/Termux was validated on 2026-10-09 in an Android 15 arm64 emulator with Termux 0.118.3. Under `nodejs-lts` (Node 24.18) the build, typecheck, full test suite and both smoke checks pass; under `nodejs` (Node 26.4) the smoke checks and the NVIDIA collateral check pass, and the tests pass once CLI-spawn timeouts allow for slower cold starts. Credential-free live appraisal passed for all three public models: one GPU in about 15 s, eight GPUs in about 20 s, with peak memory of 330–365 MB. The live Pi suite has not been run on a real device or the emulator.
- NEAR's experimental direct route sends its evidence, inference and signature requests as sequential HTTP/1.1 exchanges on one `node:tls` socket, so it no longer depends on `https.Agent`. Its [channel tests](../tests/near-direct-channel.test.ts) pass under Node and Bun, and on 2026-10-09 the Bun-compiled Pi 1.0.4 binary reached NEAR's credential check with a synthetic key: fresh evidence, CPU and GPU verification, SPKI approval and the encrypted request on the same socket. The credentialed Pi suite has not yet run under Bun.
- Reproducing the committed bytes requires the CI build directory; see [reproducibility](../tools/nvidia-verifier/README.md#reproducibility).

Written by Claude.
