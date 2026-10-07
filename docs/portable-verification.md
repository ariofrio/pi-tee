# Portable local verification

The target is a Docker-free client across Pi's supported platforms. The owned portable TLS helper is implemented and being qualified; native GPU artifact packaging is unfinished. The enabled production profile still requires the tested macOS ARM64/OrbStack environment.

## Platform and runtime scope

Pi's [binary build targets](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/scripts/build-binaries.sh) are macOS, Linux and Windows, each on x64 and ARM64. Its [Android instructions](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/docs/termux.md) also support Node in Termux, whose [package architectures](https://github.com/termux/termux-packages/wiki/Building-packages) include ARM64, ARM, x64 and x86. Cover those Android targets rather than assuming ARM64 alone establishes Termux support. Test both npm/Node Pi and its Bun-compiled desktop binaries.

Each platform must enforce the same policy. A build passing on one platform does not qualify another, and an unsupported installation must fail before an inference dispatch sends credentials or ciphertext.

## Proposed implementation

Package the CPU helper and NVIDIA's local GPU verifier as authenticated platform artifacts. Installation selects only the current platform's artifacts. Users need neither Docker nor Go, Rust or a C++ compiler. Maintainers build from locked sources and publish binaries, complete dependency inventories, hashes and build provenance.

Retain NVIDIA's verification implementation. Its [file-evidence interface](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-cli/introduction.html) separates verification from local GPU collection. A verifier-only build can omit unused collectors; platform adapters and packaging must not alter signature, certificate, reference-measurement or revocation appraisal. Package required libraries instead of relying on an arbitrary system OpenSSL/xmlsec installation. Explicitly inventory any retained OS libraries and certificate-delivery store.

The [native build candidate](../tools/nvidia-native/README.md) locks source and dependency resolution, statically links application libraries, disables unused local collectors and provides a Windows compatibility layer. On macOS ARM64 it builds as one executable linked only to OS libraries. It accepts authentic Hopper evidence and rejects wrong nonces, corrupted report/mode/certificate signatures, and corrupted reference/OCSP signatures. Untouched collateral passes through the same test delivery proxy. Builds receive a restricted environment; execution uses a hash-checked OpenSSL configuration without inherited service or crypto overrides. The six-target workflow is a qualification step; the candidate has not replaced the production verifier. Differential tests, reproducibility, final artifact inventory and integration remain unfinished.

The extension verifies the selected artifact hashes and executes private snapshots, preserving the current protection against replacement between checking and execution. Inputs and outputs remain bounded. Cancellation must terminate verifier children and the owned connection on every platform. Evidence may use private temporary files; credentials, prompts and decrypted responses must not.

Preserve the exact CPU-bound GPU report, nonce, signed NVIDIA references, all three certificate/revocation chains, local version floors and authenticated SPT-mode interpretation. The CPU/public-build chain and its freshness rules remain unchanged. Replacing local appraisal with NVIDIA's [remote verifier](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/api/group__gpu__verifier.html) would require a separate declared service/key-bootstrap contract and proof that its signed verdict applies to the exact CPU-bound report. It is not an automatic fallback.

The [owned Go transport](../tools/pinned-tls/README.md) now authenticates its socket before accepting credentials/body from the parent, sends once without redirect/reconnect/replay, and streams over bounded pipes. Its TypeScript adapter executes a hash-checked private binary snapshot and terminates it on cancellation. The candidate Tinfoil route retains EHBP encryption and response authentication. It passed real socket tests under Node 24 and Bun 1.3.13, plus actual Gemma completion, tools, reasoning, usage and cancellation in the Node CLI and official Bun-compiled Pi 1.0.4 macOS ARM64 binary. A separate compiled-binary run cancelled after a live text delta. These are host observations, not production activation or qualification of other targets.

The [transport workflow](../.github/workflows/pinned-tls.yml) runs native Node/Bun socket tests and repeated Go builds on all six desktop targets, including Windows ARM64. Its [runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) and each client's architecture are checked explicitly. The [68f0d9e run](https://github.com/ariofrio/pi-tee/actions/runs/37685243832) passed all six native Node/Bun jobs, including Windows ARM64. These results qualify the tested transport behavior, not the unfinished GPU packaging. Android execution and final platform artifact packaging remain unfinished.

Client artifact hashes vary by platform and client release. They authenticate the verifier installation; they do not freeze Tinfoil's workload releases. An ordinary attester update within the existing public publisher policy still requires no new deployment pin.

## Feasibility observations

These probes used repository commit `8b18be2` and NVIDIA SDK [9d12801](https://github.com/NVIDIA/attestation-sdk/tree/9d12801cea8a198ea0f29640dfaf8a4017c841c5). No inference request was sent and no production code or profile flag changed. [Machine-readable results](portable-verification-evidence.json).

| Probe | Observation | What remains untested |
| --- | --- | --- |
| CPU/public-build helper, `CGO_ENABLED=0` | Cross-compiles for all six desktop targets and Android ARM64. | Execution and real evidence on the other operating systems. |
| CPU helper as Go JavaScript WebAssembly | Compilation fails in in-toto's Unix filesystem-access function. | A dependency adaptation and the host HTTP bridge. WASM is not a qualified substitute. |
| NVIDIA local verifier, native macOS ARM64 | Builds with verification source unchanged; accepts authentic Hopper evidence under the existing GPU checks and rejects a wrong nonce and corrupted signature. No Docker or local GPU used. | Repeatable locked packaging, complete adversarial coverage, other platforms and integration with Pi. |
| Existing TLS tests, Bun 1.3.13 | NEAR's Agent lacks `createConnection`; Tinfoil rejects a mismatched pin, but the valid-request test times out. | A working, qualified Bun transport. No claim of a demonstrated credential leak is made. |

The native NVIDIA probe used Rust 1.90.0 and the SDK's source-built OpenSSL 3.6.1, xmlsec 1.2.39 and curl 7.88.1. CMake needed `CMAKE_POLICY_VERSION_MINIMUM=3.11`, `-Wno-error=deprecated-declarations` for fmt, and `-framework CoreFoundation` for the Rust timezone dependency. It linked macOS libxml2 and standard OS libraries. These observations establish feasibility, not a reproducible packaged verifier inventory.

Two Go library candidates were unsuitable as direct replacements: [go-nvtrust](https://github.com/confidentsecurity/go-nvtrust) delegates appraisal to NVIDIA's remote service; luxfi/cc's [RIM parser](https://github.com/luxfi/cc/blob/c35c6df61f34a7fee57c3bd5db117d3a4723fa11/attest/nvidia/rim.go) accepts a custom signed JSON format instead of NVIDIA's XML manifests. Neither was added as a dependency.

## Qualification before shipping

1. Produce locked, authenticated GPU and CPU artifacts for the platform matrix. Port only the necessary build/runtime interfaces; review any verification-code change separately.
2. Run real-signature positives and corrupted report, reference, certificate, OCSP, nonce, mode and version-floor negatives on each target. Differentially compare the GPU verdicts with the currently qualified Linux verifier.
3. Test real Node and Bun dispatch boundaries: wrong keys send nothing, a valid pinned connection works, redirects/rotation never replay, streaming authenticates, and cancellation closes all processes and sockets.
4. Exercise install, `/login`, model discovery, completion, tools, reasoning, usage and cancellation through actual Pi on each supported combination, including Windows ARM64 and the Android/Termux architectures. Cross-compilation alone does not satisfy this gate.
5. Update the client artifact inventory, authority-policy digest, setup instructions and support limits, then obtain independent review before switching production to the new verifier and transport.

NEAR's server-side session/key/runtime gaps and the model-specific Gemma serving contract are separate from client portability. Removing Docker does not qualify additional workloads.

Written by Codex.
