# Public build fixtures

These files contain public build metadata, certificates and signatures, with no machine quote, credential or inference transcript.

- `cvm-v0.11.0-manifest.json` is the exact [public guest manifest](https://images.tinfoil.sh/cvm/tinfoil-inference-v0.11.0-manifest.json), SHA256 `a7560566ca6c533f8391d3fc41df966d893b2f1d0ac7da04af8efa18ab9067f8`.
- `cvm-v0.11.0.bundle.json` is the Sigstore bundle for the [GitHub-hosted release build](https://github.com/tinfoilsh/cvmimage/actions/runs/31558890695/attempts/1), exported from GitHub's public artifact-attestations API. It authenticates source commit `a4dbce07f5b0efbee1df678026db538eba66a613` and five named artifact subjects, including that manifest.

- `gemma-v0.0.25-deployment.json` is the exact [public deployment](https://github.com/tinfoilsh/confidential-gemma4-31b/releases/download/v0.0.25/tinfoil-deployment.json), SHA256 `65f2dfa59ced010aeba841fc909880ac3434282cf2b43e90d5c3a3e543b3ccf0`. Its `.bundle.json` authenticates the named public tagged release workflow and source commit; the bundle is also publicly available through the worker's code collateral and GitHub artifact-attestations API.
- The five `gemma-v0.0.25-{index,image,config,attestation,provenance}.json` files are exact public OCI bytes rooted at [the selected GHCR image](https://github.com/tinfoilsh/confidential-gemma4-31b/pkgs/container/confidential-gemma4-31b), index SHA256 `cb45fc53829f73b588c26fa9ca6c90be122367a64e3b835ce4571a4e5f839d89`. Descriptor digests cover every checked child. The [BuildKit metadata's builder claim](https://github.com/tinfoilsh/confidential-gemma4-31b/actions/runs/31575376519/attempts/1) is endorsed by the release publisher through that digest, not independently signed by that builder. Its [declared source](https://github.com/tinfoilsh/confidential-gemma4-31b/tree/bff40cb8bd650c01be92e0f4cd98c960dbb222d9) is the release commit's parent.

The test verifies the signatures offline against the finite embedded root set. Its fixed historical version is a test vector; production guest versions come from the authenticated deployment. Build-time observer timestamps permit verification after the short-lived signing certificate expires. This establishes a historical build identity, not present CPU freshness or inference qualification.

Written by Codex.
