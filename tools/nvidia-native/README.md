# Native NVIDIA verifier candidate

This maintainer recipe builds NVIDIA's file-evidence verifier without Docker. It is unfinished and is not selected by a production provider. End-user downloads, artifact authentication, platform execution and cryptographic qualification still need to land.

`node scripts/build-native-nvidia.mjs` uses pinned NVIDIA, Regorus and vcpkg source commits, a checked-in Cargo lock and vcpkg's pinned dependency baseline. Maintainers need Git, CMake, a native C++ toolchain and Rust 1.90.0. Windows uses the static MSVC triplets. `PI_TEE_BUILD_CARGO` selects a toolchain executable; `PI_TEE_NATIVE_BUILD_DIR` selects the build directory.

The recipe preserves NVIDIA's verification sources. It replaces three unused local-device collectors with functions that reject collection. A small Windows compatibility layer supplies UTC time conversion and disabled dynamic-loader functions; it must receive separate review and target tests. The vcpkg dependency versions differ from the currently qualified Linux package, including xmlsec: a successful build alone does not establish equivalent appraisal.

The output includes the binary hash, source identities, dependency manifest and resolved package inventory. It is marked `qualified: false`. A complete artifact inventory must also authenticate retained OS libraries, certificate delivery, licenses and compiler/build provenance before shipping. Android/Termux is outside this desktop build recipe and remains work to complete.

`node --import tsx scripts/check-native-nvidia.ts` obtains fresh public Gemma GPU evidence and tests authentic evidence, wrong nonce, report-signature corruption, signed-mode corruption and certificate-signature corruption. Each negative requires NVIDIA's specific rejection code, so unrelated network failures cannot pass it. It checks the three certificate/OCSP chains, signed references, existing version floors and authenticated SPT interpretation. It sends no credentials or inference and establishes no CPU/workload admission. `PI_TEE_NATIVE_NVIDIA_BINARY` selects a binary; maintainers may supply a private `{nonce,evidence}` fixture through `PI_TEE_NATIVE_NVIDIA_TEST_EVIDENCE`. The [desktop workflow](../../.github/workflows/native-nvidia.yml) builds and executes these cases on all six desktop targets. Reference/OCSP tampering, full differential tests, Android execution, repeatable artifact packaging and final Pi integration remain required.

Written by Codex.
