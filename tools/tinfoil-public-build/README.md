# Automatic public-release and CPU verification

This evidence-only command authenticates dynamic Tinfoil release measurements and appraises fresh Intel TDX evidence. It has no built-in deployment tag/digest, guest registers, firmware reference digest or machine identifier. It sends no inference, releases no keys and appraises no GPU. Success sets `cpuVerified` and `publicBuildVerified` true, with `gpuVerified` and `inferenceQualified` false.

This separate Go module leaves the frozen [CPU research helper](../tinfoil-cpu/README.md) unchanged. It uses [Tinfoil Go revision 23734b7](https://github.com/tinfoilsh/tinfoil-go/tree/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier), Sigstore Go 1.2.2 and Go 1.26.6. Dependencies are fixed in [go.mod](go.mod)/[go.sum](go.sum). The helper verifies offline: no runtime root discovery or network access. The caller selects the local executable; this is research tooling, not an authenticated-helper installer.

## Trusted identities and processes

| Authority | Accepted scope |
| --- | --- |
| Intel | Hardware, firmware, PCS collateral signatures, revocation and validity; UpToDate appraisal. Embedded `sgx_root_ca.pem` SHA256 `267a851c8d10982685b5f219d9ac2600ba71463569a6541827c2dc9fe9d6d699`. |
| Sigstore | Only the Fulcio/Rekor/CT/timestamp keys and certificates accepted from the revision's embedded [trusted_root.json](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/provenance/trusted_root.json), SHA256 `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`. |
| GitHub | OIDC issuer `https://token.actions.githubusercontent.com`, authenticated `github-hosted` runners and the named repositories' source/workflow/release maintainers. The probe also uses GitHub public source delivery. |
| Workload publisher | `tinfoilsh/confidential-gemma4-31b/.github/workflows/tinfoil-release-publish.yml@refs/tags/vMAJOR.MINOR.PATCH`. This narrows the SDK's any-tagged-workflow rule. |
| Platform publisher | `tinfoilsh/platform-endorsements/.github/workflows/build.yml@refs/tags/vMAJOR.MINOR.PATCH`; guest firmware measurements and machine policy. |
| Freshness publisher | `tinfoilsh/freshness-witness/.github/workflows/freshness.yml@refs/heads/main`; continued acceptance of both artifacts. |
| Local execution | This code/dependency closure, compiler/runtime, OS and correct local clock. |

The embedded Sigstore bundle contains Fulcio at `fulcio.sigstore.dev`; Rekor at `rekor.sigstore.dev` and `log2025-1.rekor.sigstore.dev`; CT logs at `ctfe.sigstore.dev/test` and `ctfe.sigstore.dev/2022`; and the TSA at `timestamp.sigstore.dev/api/v1/timestamp`, with the file's exact historical key validity periods. Root changes require a verifier/policy update, not adoption from worker metadata.

Code/platform provenance authenticates repository, tag, source commit, subject and digest. Workload certificates must additionally name the exact source repository/ref, public visibility at signing and the same workflow/source commit. Each requires a matching signed freshness witness with a verified log timestamp at most seven days old and no more than five minutes in the future. An old release may remain freshly endorsed. This is not a newest-release guarantee or immediate revocation. [Provenance](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/provenance/provenance.go), [freshness](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/provenance/freshness.go).

The platform publisher authorizes boot registers/VM shape; the workload publisher authorizes workload registers. Manufacturer evidence authenticates the actual quote. Local requirements additionally enforce TD attributes `0000001000000000`, Intel QE vendor identity, componentwise TEE SVN floor `03010200000000000000000000000000` and collateral edition floor 20, preserving stronger publisher requirements.

A trusted publisher can authorize malicious code or incorrect measurements. Public evidence allows later auditing but does not guarantee it. This check establishes measured-release attribution, not an independent reproducible build. NVIDIA and the complete guest/container/model provenance and key/runtime/channel contracts still require qualification before inference admission.

## Run

```sh
mkdir -p .scratch/work
GOTOOLCHAIN=go1.26.6 go -C tools/tinfoil-public-build build \
  -mod=readonly -trimpath -buildvcs=false \
  -o ../../.scratch/work/tinfoil-public-build-verifier .
node scripts/research/tinfoil-public-build.mjs \
  .scratch/work/tinfoil-public-build-verifier \
  .scratch/work/new-public-build-evidence.json
PI_TEE_PUBLIC_BUILD_TEST_EVIDENCE="$PWD/.scratch/work/new-public-build-evidence.json" \
  go -C tools/tinfoil-public-build test -mod=readonly -v ./...
go -C tools/tinfoil-public-build vet -mod=readonly ./...
```

The Node 24 probe requests a fresh unpredictable nonce from the fixed Intel Gemma worker, passes exact raw evidence to the strict helper, authenticates downloaded deployment bytes by their signed subject digest, and compares embedded configuration bytes with public source at the authenticated commit. It passes no environment credentials to the helper. Input/responses are capped at 2 MiB; process time/output are bounded. Optional owner-only fixtures are never overwritten. The helper accepts `{ "nonce": "64 lowercase hex characters", "envelope": { ... } }` JSON on stdin; replaying a fixture establishes no new live session.

On 2026-10-07 the live probe authenticated Gemma `v0.0.25`, platform references `v0.0.16`, both freshness witnesses, the public deployment digest and exact source configuration. [Recorded metadata](../../docs/public-build-evidence.json) excludes raw quotes and keys. Real-evidence tests reject replay, absent provenance/freshness, substituted digest/repository/tag, forged software/CPU signatures and stale/future witnesses; those tests skip without the explicit fixture setting.

[Design and remaining inference gates](../../docs/design.md).

Written by Codex.
