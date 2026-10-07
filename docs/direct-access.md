# Direct-worker assessment

Observed 2026-10-07 UTC, using the locked Node 24.21.0 checkout, NEAR SDK 0.1.0 and Tinfoil SDK/verifier 1.2.2. Author: Codex.

**Direct inference worked for NEAR GLM and a Tinfoil Gemma worker with the existing API keys.** NEAR Qwen's direct quote still failed the strict TCB policy. These are SDK research results, not independently approved deployments or direct-provider end-to-end tests through Pi. Both registered extensions, the `approved` default and the `UpToDate` requirement remain unchanged.

## Observations

The [metadata-only record](direct-access-evidence.json) contains timestamps, outcomes and artifact identifiers. It contains no credentials, prompts, completions, signature records or quote bodies. Each inference probe sent a fixed synthetic request capped at 128 output tokens.

| Candidate | Observed result | What this establishes |
| --- | --- | --- |
| NEAR `z-ai/glm-5.3-flash`, `glm-5-3-flash.completions.near.ai` | CPU `UpToDate`, required GPU evidence `verified`, quote-bound TLS SPKI matched; HTTP 200, expected marker, usage and verified `provider_tee` response signature | A working strict SDK-policy direct path on one TLS connection |
| NEAR `Qwen/Qwen3.6-35B-A3B-FP8`, `qwen3-6-35b.completions.near.ai` | `policy.tcb_status_not_allowed`, actual `OutOfDate`; zero inference requests | Direct access does not universally avoid the gateway's TCB blocker |
| Tinfoil `gemma4-31b`, `gemma4-31b-inf6-3.tinfoil.containers.tinfoil.dev` | Direct SEV-SNP-v2 verification and EHBP inference succeeded; HTTP 200, expected marker and usage | A reachable model worker accepts the ordinary user API key without the decrypting model router |

### NEAR: a useful client improvement, with a remaining binding limit

The [NEAR probe](../scripts/research/near-direct.mjs) requests `include_tls_fingerprint=true`, obtains the certificate and fresh quote on one TLS 1.3 socket, checks the attested SPKI against that socket, and keeps attestation, encrypted OHTTP inference and signature lookup on it. It rejects reconnection instead of resending. Wrong-nonce and wrong-SPKI verification tests both failed with the expected binding errors. The evidence-only run also completed a second metadata request on the same socket. This follows NEAR's [direct TLS procedure](https://docs.near.ai/cloud/verification/direct/tls); the stock Node [direct client](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/node/direct-attestation-client.ts) does not request this binding by default.

This handles ordinary load-balancer connection changes and keeps instance-local signature lookup on the serving connection. It does **not** prove exclusive key custody. Another holder of the same TLS private key could terminate the client connection and relay a fresh quote binding that same SPKI; the quote contains no value unique to this TLS session. The [model signing contract](https://docs.near.ai/cloud/verification/cloud-api/model-attestations) also permits a shared model identity across differently measured instances. Encryption and a matching signature do not distinguish all recipients of those keys. A measured TLS terminator quoting its own connection's exporter would address the relay problem, but key-release policy, authenticated full guest-image appraisal, runtime changes and CPU–GPU/forwarding closure would still need independent qualification. See the [security contract](../SECURITY.md#provider-specific-blockers).

The GPU result means the required SDK check accepted NVIDIA's overall remote verdict. It does not locally appraise every device/reference policy or prove CPU–GPU association. Direct access preserves this limitation. [GPU verifier](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/utils/nvidia.ts).

The sampled report covered one instance. NEAR still documents direct completions as experimental, incomplete instance inventories and possible signature `404`s on other connections; [cloud-api#1087](https://github.com/nearai/cloud-api/issues/1087) remains open. The public [endpoint registry](https://completions.near.ai/endpoints) is a routing hint: a future extension must intersect it with the public chat/tool catalog and validate matching model metadata, not admit every registry entry. [Direct-completions documentation](https://docs.near.ai/cloud/experimental/direct-completions).

### Tinfoil: the strongest first Approved candidate

A verified router metadata request to `/.well-known/tinfoil-proxy` supplied candidate worker/repository mappings; the [router's status implementation](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/manager/manager.go) exposes these mappings. Discovery did not authorize the worker: the [Tinfoil probe](../scripts/research/tinfoil-direct.mjs) separately verified its bundle against `tinfoilsh/confidential-gemma4-31b` and addressed that worker directly through EHBP.

The SDK accepted release **`v0.0.25`**, deployment-artifact SHA-256 **`65f2dfa59ced010aeba841fc909880ac3434282cf2b43e90d5c3a3e543b3ccf0`**. Downloading the public [release artifact](https://github.com/tinfoilsh/confidential-gemma4-31b/releases/download/v0.0.25/tinfoil-deployment.json) produced the same digest. Its embedded configuration identifies CVM `v0.11.0`, an immutable container digest and hash-addressed main/assistant model packages. This is an authenticated deployment-artifact identifier, not independent software approval or a substitute for appraising the CPU launch measurement. The artifact, build and all dependencies must be reviewed as a unit. [Release and source](https://github.com/tinfoilsh/confidential-gemma4-31b/releases/tag/v0.0.25).

Direct EHBP removes the decrypting router and its moving backend-release policy from the prompt path. The SDK still authorizes provider tags, supplies neither a local rollback floor nor AMD certificate-revocation checks, and automatically re-attests/resends on rotation. Approved mode therefore needs its own transport using lower-level bundle verification, exact independently approved artifact/measurement policy and `ehbp`, with approval before every first send or rotation. [SDK recovery](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts#L370), [SEV chain checks](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/verifier/src/sev/cert-chain.ts).

No client-side GPU/device verification was demonstrated for this worker. A fresh `/.well-known/tinfoil-attestation/v3?nonce=…` probe returned **404**. Newer public CVM code implements this route and boot-generated keys, but it was not established as the tested `v0.11.0` artifact's code; do not transfer those properties to this deployment without the artifact audit. The reviewed shim can delegate API-key validation to a control plane using key/domain/path metadata. Its full runtime and plaintext-access capabilities still need review. [Newer shim](https://github.com/tinfoilsh/cvmimage/blob/46c2430be746e1ad2d783046252d825a77c3f2b1/tinfoil/cmd/shim/api.go), [key generation](https://github.com/tinfoilsh/cvmimage/blob/46c2430be746e1ad2d783046252d825a77c3f2b1/tinfoil/internal/attestedkeys/store.go).

The router described sampled GPT-OSS and other Gemma workers as TDX. Direct HTTPS attempts to `gpt-oss-120b-inf12-0` and `gemma4-31b-inf10-0` timed out after 20 seconds from this host; this is not proof of universal unreachability. The current JS verifier cannot qualify TDX. A credential-free `X-Tinfoil-Enclave-Url` relay experiment returned SEV evidence rather than the expected worker's TDX evidence, so an opaque worker relay remains unproven. No prompts were sent to these candidates. TDX would need a separately reviewed verifier with pinned hardware references; the older [Go client's reference-selection policy](https://github.com/tinfoilsh/tinfoil-go/blob/05e817920780362d6c79b0035902d51bd608918b/verifier/client/client.go#L264) is not an Approved shortcut.

## Implementation direction

Make the reachable Tinfoil SEV worker the first candidate for an independently approved profile. NEAR GLM is suitable for an explicitly experimental **SDK-policy** direct route, with the same-socket gate above; an Approved NEAR profile still needs demonstrated server/key/runtime contracts.

For either extension, route selection should be explicit and independent of the existing policy and model-visibility settings. Resolve a canonical endpoint/model before payload serialization, retain the final body/header/tool guards, appraise the actual connection before sending credentials or inference bytes, and never fall back automatically to the gateway, router or another worker after failure. Use existing native API-key login and model-refresh storage. NEAR must retain its signature barrier before exposing text or tool calls.

Before enabling a route through Pi, test socket loss between quote and send, replacement certificates, mismatched model/repository, stale or rolled-back evidence, signature `404`, rotation, cancellation, and tool follow-ups. Observe the external network seam to prove rejected gates transmit zero prompt/tool-result bytes and trigger no Pi retry. Approved qualification additionally requires the [closed artifact/key/process inventory](../SECURITY.md#required-closed-inventory), hardware/GPU appraisal, runtime closure, independent verifier/transport review and a whole-session physical-provider dispatch guard. A research success alone cannot enable it.

## Reproduce

From the locked checkout after `npm ci --ignore-scripts`, with Node 24.21.0:

```sh
node scripts/research/near-direct.mjs
node scripts/research/tinfoil-direct.mjs
node scripts/research/near-direct.mjs qwen3-6-35b.completions.near.ai Qwen/Qwen3.6-35B-A3B-FP8
```

These are evidence/metadata-only. The Qwen command exited nonzero for the observed policy rejection. Live results can change; worker hostnames and releases are not stable service contracts. The NEAR prototype overrides SDK transport methods and is not a production API compatibility promise.

The following opt-in commands send a billable fixed synthetic request. Use an owner-only dotenv file containing only the relevant provider key; never put a credential in command arguments:

```sh
node --env-file=/path/to/private/nearai.env scripts/research/near-direct.mjs --infer
node --env-file=/path/to/private/tinfoil.env scripts/research/tinfoil-direct.mjs --infer
```

Output is metadata-only. `logicalChatRequests` counts caller operations; it does not measure Tinfoil's SDK-internal wire resends. These probes do not exercise Pi login, tools, reasoning or cancellation. The separate [Pi validation record](implementation.md#validation) remains unchanged.

After a fresh locked install, `npm run check` passed all 31 tests; compiled-loader/native-login and isolated-package smokes also passed. Neither package's default inference gate was relaxed.

Written by Codex.
