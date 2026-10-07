# Public guest-build fixtures

These files contain public build metadata, certificates and signatures, with no machine quote, credential or inference transcript.

- `cvm-v0.11.0-manifest.json` is the exact [public guest manifest](https://images.tinfoil.sh/cvm/tinfoil-inference-v0.11.0-manifest.json), SHA256 `a7560566ca6c533f8391d3fc41df966d893b2f1d0ac7da04af8efa18ab9067f8`.
- `cvm-v0.11.0.bundle.json` is the Sigstore bundle for the [GitHub-hosted release build](https://github.com/tinfoilsh/cvmimage/actions/runs/31558890695/attempts/1), exported from GitHub's public artifact-attestations API. It authenticates source commit `a4dbce07f5b0efbee1df678026db538eba66a613` and five named artifact subjects, including that manifest.

The test verifies the signatures offline against the finite embedded root set. Its fixed historical version is a test vector; production guest versions come from the authenticated deployment. Build-time observer timestamps permit verification after the short-lived signing certificate expires. This establishes a historical build identity, not present CPU freshness or inference qualification.

Written by Codex.
