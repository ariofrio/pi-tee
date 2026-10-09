# Build and qualify verifier artifacts

Follow [CONTRIBUTING](../../CONTRIBUTING.md). The [NVIDIA build inventory](../../tools/nvidia-verifier/README.md) owns source/toolchain locks, reviewed patches, prerequisites, license generation and reproducibility limitations. The [Go helper](../../tools/tinfoil-public-build/README.md) owns its CLI/input contract. Runtime sandbox mechanics belong beside their source.

1. Use locked Node 24, Go 1.26.6 and Rust 1.90.0; install the source-lock recipe's prerequisites.
2. Run `npm run build:wasm`. `--go-only` rebuilds only the CPU helper, but does not replace the required full independent CI rebuild for verifier changes.
3. Check module pins, glue and third-party notices. Pins cover uncompressed bytes; gzip can vary across zlib versions. Comment changes can change Go line metadata and therefore the WASM hash even without executable logic changes.
4. Run the [WebAssembly verifier workflow](../../.github/workflows/wasm-verifiers.yml). Its fixed `/home/runner/pi-tee-wasm-build` path reproduces NVIDIA's path-dependent Rust symbols, compares pins and decompressed archives, and tests Node/Bun hosts on six desktop targets. Commit CI-built artifacts.
5. Run `npm run check:nvidia` (add `-- --collateral` for full collateral negatives), Go format/vet/tests, affected Node/Bun tests and required package smokes. Wrong-result codes and delivery failures cannot pass policy negatives.
6. Record the exact source commit, artifact digests, CI/rebuild and host results. Pushes to main additionally attest shipped files and uncompressed modules; verify a shipped artifact with `gh attestation verify <file> -R ariofrio/pi-tee`.

Build success is reproducibility evidence, not fresh serving or inference qualification. Keep outcomes in the [evidence index](../evidence/README.md).
