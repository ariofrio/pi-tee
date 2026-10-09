# WebAssembly verifiers

`node scripts/build-wasm-verifiers.mjs` builds two verifiers:

- **`nvattest.wasm.gz` and `nvattest.mjs`** in [`packages/core/wasm`](../../packages/core/wasm): NVIDIA's local file-evidence verifier, compiled with Emscripten and shared by both providers.
- **`tinfoil-public-build.wasm.gz`** in [`packages/tinfoil/wasm`](../../packages/tinfoil/wasm): the [public-build CPU and release verifier](../tinfoil-public-build/README.md), compiled as a WASI command.

Users need no compilers, containers or downloads: each package checks its files against [`nvidia-artifacts.ts`](../../packages/core/src/nvidia-artifacts.ts) or [`wasm-artifacts.ts`](../../packages/tinfoil/src/wasm-artifacts.ts) before compiling or importing them, and uses the checked bytes rather than reading the file again. The same bytes run on every Pi platform, under both Node and Bun.

## Sources and changes

[`source-lock.json`](source-lock.json) pins the NVIDIA SDK, Regorus, vcpkg and Emscripten SDK commits, Rust 1.90.0 and Go 1.26.6. It also pins the SHA-256 of each archive the Emscripten SDK installs on Linux and macOS hosts (LLVM, Binaryen and Emscripten, Node, and on macOS Python); the build places the checked archives where emsdk installs from. vcpkg resolves the C/C++ dependencies from its pinned baseline and [`vcpkg.json`](vcpkg.json), except OpenSSL, which comes from the pinned vcpkg port through the patched overlay below; Cargo uses the checked-in [`regorus.Cargo.lock`](regorus.Cargo.lock); Go uses the helper's `go.sum`.

NVIDIA's verification sources are unchanged except for hash-locked patches, each requiring independent review:

- [`rim-leaf-signature.patch`](patches/rim-leaf-signature.patch) hardens reference-manifest (RIM) appraisal:
  - It verifies signatures with the leaf certificate that the chain check appraises.
  - It requires NVIDIA's signature layout: no DTD; one signature, the root's last element, holding `SignedInfo`, `SignatureValue` and `X509Data` certificates; and one whole-document reference with only the enveloped-signature and C14N 1.1 transforms. Layout violations are signature rejections (NVIDIA code 105).
  - It reads the version, manufacturer, measurements and certificates only from their fixed signed locations, and requires exactly one version `Meta`.
  - It ignores manifests and allows only the enveloped-signature, C14N 1.1 and SHA-384 reference transforms.
- [`collectors-disabled.cpp`](collectors-disabled.cpp) replaces NVIDIA's three local-GPU collectors with functions that reject collection.
- [`nv-http-host.cpp`](nv-http-host.cpp) replaces the libcurl transport with a request bridge to the host. It sends each request once; NVIDIA's client retried 5xx and 429 responses. NVIDIA's sources still include libcurl headers, but none of its code is linked.

The Go helper's own source is in [`tools/tinfoil-public-build`](../tinfoil-public-build/README.md). Its vendored copy of in-toto replaces one Unix-only file-writability check that verification never calls ([replacement](../tinfoil-public-build/wasi/in_toto_util_unix.go.in)).

## Runtime boundary

Each verifier runs in a worker thread that is terminated on cancellation or after a timeout.

- The CPU helper runs under the minimal [WASI shim](../../packages/core/src/wasi.ts): arguments, `TZ=UTC`, clocks, randomness and bounded stdin/stdout. It has no preopened directories or sockets.
- The NVIDIA verifier's only network path is the [request bridge](../../packages/core/src/nvattest-bridge.ts). It admits `GET https://rim.attestation.nvidia.com/v1/rim/<id>` and `POST https://ocsp.ndis.nvidia.com`, with bounded bodies, no redirects or credentials, and at most 192 requests (eight GPUs need about 88). Under Node the worker ignores proxy settings; Bun's `fetch` applies `HTTP_PROXY` and `HTTPS_PROXY`, though TLS still ends at NVIDIA. Evidence is written to an in-memory file system. Emscripten's environment is isolated from the host's, so `OPENSSL_*` and NVIDIA service overrides cannot reach it.

## Reproducibility

Pins cover the uncompressed modules, since gzip output varies between zlib versions. The Go helper, JavaScript glue and license inventory are byte-identical across build directories and between macOS and Linux. The NVIDIA module is not: Cargo hashes the absolute path of Regorus, an out-of-workspace path dependency, into symbol names. Its committed copy therefore comes from the [CI workflow](../../.github/workflows/wasm-verifiers.yml), which builds in `/home/runner/pi-tee-wasm-build`, uploads the result and fails if a pin differs from the rebuild. Pushes to `main` also record GitHub build-provenance attestations for the committed archives and glue, once the archives are shown to decompress to the rebuilt modules, and for the uncompressed modules; `gh attestation verify <file> -R ariofrio/pi-tee` checks any shipped file.

The triplet removes vcpkg and Emscripten source paths from objects. A hash-locked [port patch](patches/vcpkg-openssl-fixed-paths.patch) and a triplet option fix the OpenSSL module/engine and libxml2 catalog paths that would otherwise embed the build root.

Maintainers need Git, CMake, a C/C++ host toolchain, Rust 1.90.0 with the `wasm32-unknown-emscripten` target, and Go. `PI_TEE_BUILD_CARGO` selects Cargo; `PI_TEE_WASM_BUILD_DIR` selects the build directory. The build also writes a `THIRD_PARTY_LICENSES.txt` beside each module: [NVIDIA's](../../packages/core/wasm/THIRD_PARTY_LICENSES.txt) covers NVIDIA, the Emscripten runtime, every vcpkg port and Rust crate linked into it, and [the helper's](../../packages/tinfoil/wasm/THIRD_PARTY_LICENSES.txt) every Go module.

## Checks

[`check-nvidia-verifier.ts`](../../scripts/check-nvidia-verifier.ts) appraises fresh public Gemma (one Hopper) GPU evidence through the WebAssembly verifier; live appraisal of the eight-GPU Blackwell workers exercises the multi-GPU path. It checks authentic evidence and rejects a wrong nonce and corrupted report, signed-mode, certificate, reference-manifest and OCSP signatures. It also rejects driver manifests whose layout differs from NVIDIA's, built from the genuine manifest: an extra `KeyInfo` element, a signature that is not the root's last element, a `ds:Object`, a manifest reference and a DTD (105), and a duplicate version `Meta` (106). A loopback proxy relays authentic NVIDIA collateral as the positive control for the collateral cases. Each negative requires a specific NVIDIA result code; delivery errors cannot pass. Under Node, a verifier process started with proxy settings must still reach the relay directly. No credentials or inference are sent. [`wasm-verifiers.test.ts`](../../tests/wasm-verifiers.test.ts) covers artifact authentication, the absent file system, the shim's import and memory bounds, cancellation (including before a worker starts), an offline release authentication, and the request bridge: a stub `fetch` checks its destinations, forwarded headers, redirect setting, size limits and request cap.

Written by Claude.
