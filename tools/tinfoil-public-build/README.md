# Automatic public-release and CPU verifier

Offline Go command and packaged WASI helper for Tinfoil CPU/release/build/runtime evidence. It sends no inference, releases no keys and appraises no GPU. Standalone success does not qualify a serving session. [Trust and serving contract](../../docs/contracts/tinfoil-public-builds.md), [source/qualification record](../../docs/evidence/tinfoil/helper-investigation.md).

Dependencies are fixed by [go.mod](go.mod)/[go.sum](go.sum): Tinfoil Go revision 23734b7, Sigstore Go 1.2.2 and Go 1.26.6. Runtime roots are embedded, without network discovery. Exact hardware floors live in [hardware policy](../../docs/reference/hardware-policy.md); authority identities and custody rules live in the serving contract.

## Run

From the locked checkout:

```sh
mkdir -p .scratch/work
npm run build
GOTOOLCHAIN=go1.26.6 go -C tools/tinfoil-public-build build \
  -mod=readonly -trimpath -buildvcs=false \
  -o ../../.scratch/work/tinfoil-public-build-verifier .
node scripts/research/tinfoil-public-build.mjs \
  .scratch/work/tinfoil-public-build-verifier \
  .scratch/work/new-public-build-evidence.json
PI_TEE_PUBLIC_BUILD_TEST_EVIDENCE="$PWD/.scratch/work/new-public-build-evidence.json" \
  GOTOOLCHAIN=go1.26.6 go -C tools/tinfoil-public-build test -mod=readonly -v ./...
GOTOOLCHAIN=go1.26.6 go -C tools/tinfoil-public-build vet -mod=readonly ./...
```

The [probe](../../scripts/research/tinfoil-public-build.mjs) requests a fresh nonce from a fixed Gemma worker and checks the artifact chain. Saved fixture replay is not a fresh session. It passes no credential to the helper, bounds inputs/output/time and never overwrites optional owner-only fixtures.

## Input and output contract

Read JSON from stdin; binary fields are base64 exact bytes. Invalid or incomplete inputs fail. Source comments explain the local authentication mechanics.

| Mode | Input / successful scope | Source |
| --- | --- | --- |
| Default | `nonce` (64 lowercase hex characters), `envelope`; authenticated CPU/release/platform/freshness. CPU/public-build true, GPU/inference false | [verifyWithPlatform()](main.go) |
| `--cvm-build` | `tag`, `manifest`, `bundle`; authenticated guest manifest/kernel/initrd/disk subject hashes. No CPU session or independent disk rebuild | [CVM verifier](cvm.go) |
| `--container-reference` | `repo`, `tag`, `deployment`, `bundle`; release-authorized engine digest. Registry tags do not select it | [container reference](container.go) |
| `--container-build` | Reference input plus `index`, `imageManifest`, `imageConfig`, `attestationManifest`, `provenance`; digest traversal and release-endorsed BuildKit metadata. Independent builder/CPU/GPU/freshness/inference false | [authenticateContainer()](container.go) |
| `--runtime-config` | Signed-release reference input; constrained `tinfoil-vllm-v1` config/model roots/flags/custody. Runtime profile true, CPU/GPU/freshness/inference false | [authenticateRuntimeRelease()](runtime.go) |

The TypeScript [artifact chain](../../packages/tinfoil/src/public-build.ts) composes these results with authenticated boot recomputation and source checks. The [worker appraisal](../../packages/tinfoil/src/worker-appraisal.ts) adds fresh hardware/GPUs and keys; the owned session/transport establishes dispatch. Source delivery, private fixtures and live observations have their [recorded limits](../../docs/evidence/tinfoil/helper-investigation.md).

[Fixture provenance](testdata/README.md), [verifier build procedure](../../docs/procedures/verifier-builds.md), [cache/session limits](../../docs/reference/support-limits.md). No maintained vendor deployment pins or runtime root updates are authorized by this command.
