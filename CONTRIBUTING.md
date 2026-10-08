# Contributing

Use the locked Node 24 workspace. Read [SECURITY.md](SECURITY.md) before changing policy, transport, model routing or verification reporting.

Test through the native provider and transport interfaces. Observe prompt transmission at the external SDK/network seam; do not mock policy or message-conversion internals. Add a failing test for security behavior before implementation. Keep provider differences in their adapters and common enforcement in the shared library.

Run `npm ci --ignore-scripts`, `npm run check`, `npm run smoke`, and `npm run smoke:packages` (which may download dependencies). The tarball check establishes package loading, login and SDK separation, not qualification of a newly resolved verifier dependency set. Catalog and attestation smokes are optional live checks with no inference. Never put keys or provider payloads in tests, logs or examples. A mocked verifier result does not qualify a deployment for production.

Changes to SDK/Pi versions require reviewing error/retry behavior, final payload coverage, key rotation, API/loader compatibility and the explicit trust disclosures. Public-build policy permits authenticated releases from its named publisher/workflow identities without maintained deployment pins. Do not silently expand those authorities or treat provider release tags as independent approval. Do not enable a production profile without all hardware, serving-path, runtime, artifact-chain and review gates. See the [current design](docs/design.md).

Changes to the WebAssembly verifiers go through `npm run build:wasm`; commit the [CI-built artifacts](tools/nvidia-verifier/README.md#reproducibility) and keep `npm run check:nvidia` passing. Update the relevant package README and [CHANGELOG.md](CHANGELOG.md) with behavior and validation. Registry publication and external submissions require the project owner's approval.
