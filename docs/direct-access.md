# Direct-worker assessment

Observed 2026-10-07 UTC. Author: Codex. Node 24.21.0; Pi 1.0.4; NEAR SDK 0.1.0; Tinfoil SDK/verifier 1.2.2; EHBP 0.3.3.

**The Tinfoil direct Gemma route now passes the complete actual Pi suite.** Fresh CPU and manufacturer-local GPU verification also passed separately. NEAR GLM supports a working direct research path, while the sampled Qwen instance still fails the strict TCB policy. Neither provider has an enabled independently Approved profile.

## Registered route and validation

`PI_TINFOIL_POLICY=sdk PI_TINFOIL_ROUTE=direct` exposes only `gemma4-31b`. The [adapter](../packages/tinfoil/src/direct.ts) pins `gemma4-31b-inf6-3.tinfoil.containers.tinfoil.dev`, repository `tinfoilsh/confidential-gemma4-31b`, the exact `v0.0.25` artifact digest, and its SEV launch measurement. ATC's optional tag is only a hint; the required tag comes from authenticated Sigstore provenance. An update cannot be adopted automatically.

The adapter uses lower-level `Verifier.verifyBundle` and EHBP instead of `SecureClient.fetch`. [TLS binding](../packages/core/src/pinned-tls.ts) checks the attested SPKI on the exact TLS 1.3 socket before transmitting API credentials or encrypted inference bytes. It sends once and rejects rotation or error responses without re-attestation, retry or fallback. The default router route remains unchanged, including its disclosed [SDK rotation resend](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts#L370).

The direct route passed compiled loading, native secret login, stored-key precedence, completion/usage, Unicode tool execution/result follow-up, reasoning/final text and RPC cancellation in one [actual Pi suite](../scripts/live-pi.ts). A separate router cancellation retry passed with `gpt-oss-120b`. The harness now uses a dedicated metadata pipe because [Pi redirects extension stdout](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/core/output-guard.ts) in RPC mode. The full suite uses a test-only one-second barrier after HTTP 200. A separate `--cancel-stream` run passed RPC abort after an actual live text delta, with that barrier disabled. This validates Pi cancellation while consuming the direct stream; remote generation-stop timing is not established. Local overload was observed, but does not establish the cause of the router's intermittent key mismatch.

A fresh locked install passed **35 tests**, full build/typechecking, compiled-loader/native-login smoke and isolated tarball smoke. [Real-socket tests](../tests/pinned-tls.test.ts) prove wrong-key rejection before any HTTP transmission; [routing tests](../tests/direct-routing.test.ts) cover canonical endpoints and stale selections; [artifact tests](../tests/tinfoil-direct.test.ts) reject worker/digest/tag substitution before inference. Stronger v3/GPU research checks below are not yet enforced by the registered JS route.

## Tinfoil candidate qualification

The [metadata record](direct-access-evidence.json) contains outcomes and public artifact identifiers, without credentials, prompts, completions, signature records or quote bodies. Initial SDK research used synthetic requests capped at 128 tokens; actual Pi tests cap each request at 1024 tokens.

| Check | Observed result | Limit |
| --- | --- | --- |
| Direct serving | HTTP 200, expected synthetic marker and usage, existing API key | One pinned worker; no fleet-wide claim |
| Artifact | Public deployment JSON matches authenticated SHA-256 `65f2dfa59ced010aeba841fc909880ac3434282cf2b43e90d5c3a3e543b3ccf0` | Independent source/build approval remains required |
| Fresh v3 CPU | Nonce-bound quote, AMD signature/revocation and complete SDK reference-policy appraisal passed; exact artifact and launch measurement matched | Research helper currently accepts provider reference/freshness authorities |
| CPU-bound sections | Wrong nonce, changed keys and changed GPU evidence rejected | These negatives are not a complete adversarial suite |
| Manufacturer-local GPU | NVIDIA verifier 1.2.2 accepted the CPU-bound evidence: report signature/nonce, driver/VBIOS RIM signatures and measurements, three good OCSP results | Not yet integrated into Pi; exact appraisal policy must be reviewed and pinned |
| GPU negatives | Forged signature → `GPU Evidence Invalid Signature`; wrong nonce → `GPU Evidence Nonce Mismatch` | Real manufacturer verifier, no inference |

The correct fresh route is `/.well-known/tinfoil-attestation?nonce={fresh32bytes}`. It returned v3 evidence with one GPU. The earlier `/tinfoil-attestation/v3` request's 404 came from probing the wrong path and did not establish absence of fresh evidence. The exact deployed [CVM v0.11.0 shim](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/shim/api.go#L330) implements this route. Its [envelope construction](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/attestation/attestation.go#L148) binds the nonce, TLS/HPKE keys and exact GPU evidence bytes into CPU REPORT_DATA. This is stronger than independent CPU/GPU reports.

The guest's Go verifier revision `ff634ede9513` authenticated CPU evidence and AMD revocation but rejected current platform reference values with `unknown object member "iommu_write_safe"`. Research switched to exact revision `23734b7c6b9acf5359087412b03ebb524c2fb2f1`, which [recognizes and enforces the field by CPU product](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/quote/sev/expectations.go#L144). Full fresh verification then passed. No unknown-field bypass was added. The research [v3 verifier](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/client/verify.go#L72) authenticates code, platform endorsements and freshness witnesses; local exact measurements/security floors must replace those ongoing provider authorities for Approved use.

NVIDIA's [official 1.2.2 manifest](https://developer.download.nvidia.com/compute/nvat/redist/redistrib_1.2.2.json) supplies the Linux ARM artifact SHA-256 `720455eb71d3aca50dc9fbd0900b0fa72fe36b6500fb5c5d453e7f4e9300187c`; the downloaded bytes matched. An isolated local Linux container ran that verifier with file-sourced evidence and local appraisal. It received no API key or inference content. Results identify GH100, driver `595.71.05` and VBIOS `96.00.D0.00.03`. Manufacturer RIM and OCSP services supplied signed collateral. [Evidence/nonce verification](https://github.com/NVIDIA/attestation-sdk/blob/9d12801cea8a198ea0f29640dfaf8a4017c841c5/nv-attestation-sdk-cpp/src/gpu/evidence.cpp#L240), [local appraisal](https://github.com/NVIDIA/attestation-sdk/blob/9d12801cea8a198ea0f29640dfaf8a4017c841c5/nv-attestation-sdk-cpp/src/gpu/verify.cpp#L60).

### Artifact, key and runtime evidence

The [release artifact](https://github.com/tinfoilsh/confidential-gemma4-31b/releases/download/v0.0.25/tinfoil-deployment.json) matches the pinned digest. The exact model source is commit `43dc8f6d1c4d9c1504559ab181cf9dfe00ad239b`; CVM v0.11.0 is commit `a4dbce07f5b0efbee1df678026db538eba66a613`.

| Boundary | Evidence in the exact deployed sources |
| --- | --- |
| Configuration | [Measured configuration hash and bounded strict decoding](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/boot/config.go); operator environment/secrets affect only declared inputs |
| Model bytes | [Pinned main/assistant model roots and revisions](https://github.com/tinfoilsh/confidential-gemma4-31b/blob/43dc8f6d1c4d9c1504559ab181cf9dfe00ad239b/tinfoil-config.yml#L6), [dm-verity mounting](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/boot/models.go#L27) |
| Container bytes | Immutable image `cb45fc53829f73b588c26fa9ca6c90be122367a64e3b835ce4571a4e5f839d89`; [digest enforcement](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/containers/containers.go#L626) |
| Key custody | [Guest-generated TLS key and HPKE identity](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/boot/identity.go), [private ramdisk paths](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/boot/paths.go); model containers receive the public directory |
| Engine isolation | [Readonly root, all capabilities dropped, no-new-privileges and public-only mount](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/containers/containers.go#L469) |
| Engine egress | The Gemma configuration declares no egress network; its [implicit shim network is closed](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/firewall/containers.go#L44). This does not establish every guest process's egress policy |
| GPU admission | [Manufacturer-local verification before ready-state enablement](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/cmd/boot/gpuattest.go#L190), [exact NVIDIA SDK/dependency pins](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/nix/nvattest.nix) |
| Authentication | [Control-plane request contains API key/domain/host/path](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/key/key.go#L10); [response status only authorizes/rejects](https://github.com/tinfoilsh/cvmimage/blob/a4dbce07f5b0efbee1df678026db538eba66a613/tinfoil/internal/key/online/verify.go). The provider retains credential/billing authority |
| Build inputs | [Digest-pinned vLLM base, checksum-pinned wheels and reviewed patch list](https://github.com/tinfoilsh/confidential-gemma4-31b/blob/43dc8f6d1c4d9c1504559ab181cf9dfe00ad239b/Dockerfile) |

These establish concrete source properties, not an exhaustive audit of kernel, driver, runtime dependencies or all plaintext-capable processes. Model correctness and traffic-analysis resistance remain outside the security claim. The router-specific `user_cache_secret` field is encrypted on the direct route; engine cache-namespace enforcement has not been established from that field.

The observed research trust set includes local Node/Go/Linux/container runtimes and pinned verifier dependencies; AMD hardware/endorsement/revocation authorities; NVIDIA hardware, device/RIM signing and OCSP authorities; Sigstore roots/log/timestamp processes and GitHub identities/builds; and Tinfoil's code, platform-endorsement and freshness-witness approval processes. HTTPS/WebPKI participates in initial artifact acquisition. The registered direct JS route additionally lacks fresh nonce/revocation/GPU enforcement. A locally approved immutable manifest and vendor-only appraisal can remove ongoing provider release/reference selection from authorization; delivery can still deny service. [Required complete inventory](../SECURITY.md#required-closed-inventory).

## NEAR direct research

GLM at `glm-5-3-flash.completions.near.ai` passed CPU `UpToDate`, required GPU evidence, same-TLS SPKI binding, encrypted OHTTP inference, expected marker/usage and a verified `provider_tee` response signature. Qwen at `qwen3-6-35b.completions.near.ai` failed `policy.tcb_status_not_allowed` with `OutOfDate`, before inference. The [probe](../scripts/research/near-direct.mjs) uses one TLS 1.3 socket for quote, inference and signature lookup, and rejects reconnection. Wrong nonce and wrong SPKI reject. [Direct TLS procedure](https://docs.near.ai/cloud/verification/direct/tls), [SDK direct client](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/node/direct-attestation-client.ts).

That closes ordinary connection changes, but a holder of the shared TLS key could still terminate a client connection and relay a quote binding the same SPKI. No quote value identifies this TLS session. NEAR's [shared model signing contract](https://docs.near.ai/cloud/verification/cloud-api/model-attestations) permits differently measured instances. A measured terminator quoting its actual TLS exporter could close evidence relay; full guest-image appraisal, key-release/mutation controls and downstream/GPU closure still require evidence. The required [GPU SDK check](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/utils/nvidia.ts) accepts NVIDIA's remote verdict, without proving CPU–GPU association.

NEAR describes direct completions as experimental, with incomplete instance inventories and possible signature `404`s on other connections. [cloud-api#1087](https://github.com/nearai/cloud-api/issues/1087), [direct-completions documentation](https://docs.near.ai/cloud/experimental/direct-completions). The registered NEAR extension still uses its strict gateway route; its `OutOfDate` block is unchanged.

## Reproduce and remaining implementation

```sh
# Public evidence/metadata only, using Node 24.21.0 in the locked checkout:
node scripts/research/near-direct.mjs
node scripts/research/tinfoil-direct.mjs

# Billable synthetic actual-Pi suite; owner-only file with the relevant key:
PI_TINFOIL_ROUTE=direct node --env-file=/path/to/private/tinfoil.env --import tsx scripts/live-pi.ts tinfoil gemma4-31b
# Append --cancel-only for cancellation at response headers, or --cancel-stream
# to abort after a live text delta without the test consumption barrier.
```

The initial research probes use the provider SDK; their logical request count does not account for SDK wire resends. The new registered direct route owns a single send. Worker availability and references may change; pin mismatches must remain terminal.

Next, integrate fresh vendor CPU/GPU appraisal with a locally pinned manifest; finish the complete runtime/key/channel inventory and independent verifier/transport review. NEAR needs an explicit same-socket SDK candidate and, for Approved use, a demonstrated server/session contract. Whole-session protection still requires Pi's fail-closed physical-provider dispatch guard. These are separate from the working direct route and its passed live suite.

Written by Codex.
