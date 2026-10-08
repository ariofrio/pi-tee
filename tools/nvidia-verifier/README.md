# Native NVIDIA verifier candidate

This maintainer recipe builds NVIDIA's file-evidence verifier without Docker. It is unfinished and is not selected by a production provider. End-user downloads, artifact authentication, platform execution and cryptographic qualification still need to land.

`node scripts/build-native-nvidia.mjs` uses pinned NVIDIA, Regorus and vcpkg source commits, a checked-in Cargo lock and vcpkg's pinned dependency baseline. Maintainers need Git, CMake, a native C++ toolchain and Rust 1.90.0. Windows uses the static MSVC triplets. `PI_TEE_BUILD_CARGO` selects a toolchain executable; `PI_TEE_NATIVE_BUILD_DIR` selects the build directory.

The recipe preserves NVIDIA's verification sources except for hash-locked patches, each requiring independent review. [`rim-leaf-signature.patch`](patches/rim-leaf-signature.patch) verifies reference-manifest signatures with the leaf certificate the chain check appraises. It replaces three unused local-device collectors with functions that reject collection. A Windows compatibility layer supplies alternative operator tokens, UTC time conversion, disables dynamic loading and removes a conflicting logging macro. The vcpkg dependency versions differ from the currently qualified Linux package, including xmlsec; they require differential tests and target execution.

Build subprocesses receive an allowlisted toolchain environment and an isolated Cargo home. The output includes a hash-checked OpenSSL configuration using the built-in default provider. The check script authenticates that configuration before fetching evidence and excludes inherited NVIDIA service URLs, proxies and OpenSSL overrides. These controls must also hold in the eventual production adapter.

The output includes the binary hash, source identities, dependency manifest and resolved package inventory. It is marked `qualified: false`. A complete artifact inventory must also authenticate retained OS libraries, certificate delivery, licenses and compiler/build provenance before shipping. Android/Termux is outside this desktop build recipe and remains work to complete.

`node --import tsx scripts/check-native-nvidia.ts --collateral` obtains fresh public Gemma GPU evidence. It tests authentic evidence and corrupted nonces, report signatures, signed mode, certificate signatures, reference signatures and OCSP signatures. A loopback delivery proxy provides an untouched positive control for the collateral cases. Each negative requires a specific NVIDIA rejection code or failed signature claim; delivery errors cannot pass. Checks cover the three certificate/OCSP chains, signed references, version floors and authenticated SPT interpretation. No credentials or inference are sent, and no CPU/workload admission is established.

`PI_TEE_NATIVE_NVIDIA_BINARY` selects a binary; `PI_TEE_NATIVE_NVIDIA_CONFIG` selects its pinned configuration. Maintainers may supply a private `{nonce,evidence}` fixture through `PI_TEE_NATIVE_NVIDIA_TEST_EVIDENCE`. The [desktop workflow](../../.github/workflows/native-nvidia.yml) builds and executes the cases on all six desktop targets. Full differential tests, Android execution, repeatable artifact packaging and final Pi integration remain required.

Written by Codex.
