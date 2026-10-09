# Why NEAR public builds cannot be enabled

**Preserved investigation / validation record.** Source snapshot: [main at fa5e154](https://github.com/ariofrio/pi-tee/commit/fa5e1547d4a99a8f40b0279f08aa24f9bcaa03b9). Earlier commands, availability claims and remaining-work statements describe their original scope. Use the [provider guide](../../providers.md) for current adapter behavior. Substantive claims and verdicts below are retained; relocation only changes local links.

**NEAR support is implemented, but its `public-builds` guarantee cannot be established for any current NEAR model.** NEAR's operator chooses the serving software at runtime, and that software can use the instance's TLS key and the app-wide keys that sign responses and decrypt end-to-end-encrypted payloads. A client can authenticate what one instance has deployed so far, but not that public release processes authorize the software that will serve its request. No client-side check can close that gap; it needs a NEAR server change.

The current routes require a provider-and-host-trusting position. Direct discovery now includes GLM-5.3 Flash and tool-capable Qwen models, with per-request H1/H2 appraisal and G3; [discovery and live validation](https://github.com/ariofrio/pi-tee/blob/fa5e1547d4a99a8f40b0279f08aa24f9bcaa03b9/docs/near-direct-discovery.md) describe the current behavior. Earlier `sdk` route observations below are historical. This is our assessment of NEAR's published code and live attestation evidence, not a NEAR-published statement. No inference was sent to gather it.

## Own-fleet models

These are the attestation-declared `vllm` models served by NEAR's own CVMs, such as GLM-5.3 Flash and Qwen3.6.

### Operators choose the serving software at runtime

Each measured base compose includes a **compose-manager** that deploys the actual workload after boot ([source `f91a2045`](https://github.com/nearai/compose-manager/blob/f91a204549b64218a92c9bada84f8129de3c1f45/src/main.rs)):

- It is root-equivalent. The measured compose gives it `pid: host`, `SYS_ADMIN` and `SYS_PTRACE` so it can `nsenter` into PID 1, plus `/var/run/docker.sock` and `/var/run/dstack.sock`, the quote and key-derivation socket.
- A request bearing the operator's token deploys `prod/*.yaml` from `nearai/cvm-compose-files` at *any* Git ref ([`validate_tag`/`fetch_github_file`, L837–873](https://github.com/nearai/compose-manager/blob/f91a204549b64218a92c9bada84f8129de3c1f45/src/main.rs#L837-L873); [token check, L877](https://github.com/nearai/compose-manager/blob/f91a204549b64218a92c9bada84f8129de3c1f45/src/main.rs#L877)). No release signature, workflow identity or image provenance is checked.
- "Any Git ref" includes commits that exist only in someone else's fork: GitHub serves fork-network commits through the parent repository's API and raw URLs, which are the two endpoints compose-manager uses. On 2026-10-08 a commit present only in a fork of `nearai/cloud-api` returned 200 from both parent URLs.
- The compose file may build images inside the CVM (`build:`, including `dockerfile_inline`), as NEAR's own `prod/GLM-5.1-SGL-AWQ-TP4.yaml` does. Such images have no registry digest or provenance at all; they are whatever the file's build steps produce. Operator-supplied environment values are also passed to Compose as `--env-file` and are checked only for key syntax.
- Its only age gate trusts the commit's self-declared committer date. The binary defaults to 48 hours and the repository's launcher to 2, but the live measured base compose (the one `compose_hash` covers) sets `MIN_TAG_AGE_HOURS=${CM_MIN_TAG_AGE_HOURS:-0}`, an operator-supplied value that defaults to zero ([binary default](https://github.com/nearai/compose-manager/blob/aa9de34419c753c432259ecbcc717b6e2a7357c6/src/main.rs#L3902-L3905), [launcher](https://github.com/nearai/compose-manager/blob/aa9de34419c753c432259ecbcc717b6e2a7357c6/launcher/docker-compose.yml#L27)).
- Deployed containers can reach the instance's TLS private key, which `certbot` keeps in a Docker volume. Through the dstack socket, they can also derive the response-signing keys.

The manager image itself is more constrained: a launcher replaces it only with images cosign-signed by a `nearai/compose-manager` workflow (`LAUNCHER_COSIGN_IDENTITY_REGEXP=https://github.com/nearai/compose-manager/.github/workflows/.*`, any workflow or ref).

The quoted action logs show how deployments work in practice. On 2026-10-07, the GLM-5.3 Flash worker ran an untagged experiment commit from a feature branch, about five hours after it was committed, before returning to a release tag. On 2026-10-08 it deployed feature-branch commit `87b48f1` four minutes after it was committed, and the Qwen3.6 worker deployed two feature-branch commits four and five seconds after they were committed. The quote binds each log's hash to the client's nonce, so the client can authenticate the record. The record shows what the operator deployed; it does not show that a public release process authorized it.

The record is also only as honest as the deployments it describes. compose-manager obtains the quote from dstack's ordinary `GetQuote` call with `report_data = SHA256(actions) ‖ nonce` ([L2659–2664](https://github.com/nearai/compose-manager/blob/f91a204549b64218a92c9bada84f8129de3c1f45/src/main.rs#L2659-L2664)); nothing is extended into an append-only register. The deployed proxy that relays this report to clients runs `privileged: true` with `/var/run/dstack.sock` mounted ([GLM-5.3 Flash compose, L72–77](https://github.com/nearai/cvm-compose-files/blob/1121ee56851dcec7dc89e60099d7be28fc51a73e/prod/GLM-5.3-Flash-SGL-TP4-W4AFP8.yaml#L72-L77)). A deployment that replaces it can therefore return a genuine quote over a fabricated, clean-looking log. The log itself is a plain `actions.json` file in compose-manager's work volume, and a corrupt file reads as an empty log ([L138–151](https://github.com/nearai/compose-manager/blob/aa9de34419c753c432259ecbcc717b6e2a7357c6/src/main.rs#L138-L151)). The log reliably exposes deployments that are not trying to hide, such as the feature-branch experiments above, but not a malicious or compromised operator.

### Signing and decryption keys are app-wide

Response-signing keys come from dstack's KMS: `get_key("<model>/ecdsa-signing-key")` and the Ed25519 equivalent ([inference-proxy `0f37728`, `signing.rs` L149–176](https://github.com/nearai/inference-proxy/blob/0f37728af5387d4805a12db133662d769a679373/src/signing.rs#L149-L176)). KMS keys derive from the *app's* root, so every CVM admitted for that app can derive every model's signing key. On 2026-10-07, the GLM-5.3 Flash and Qwen3.6 workers reported the same `app_id` (`2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b`), with different OS images (`dstack-nvidia-0.5.11`, `0.5.5`) and compose hashes. A valid response signature therefore shows only that some CVM of this app produced it. The keys that decrypt end-to-end-encrypted request fields and model-side OHTTP derive from the same app-wide seed ([encryption.rs L398–420](https://github.com/nearai/inference-proxy/blob/00c250e425946871597c0ab50544515182594045/src/encryption.rs#L398-L420), [ohttp_gateway.rs L9–11](https://github.com/nearai/inference-proxy/blob/00c250e425946871597c0ab50544515182594045/src/ohttp_gateway.rs#L9-L11)), so any CVM of the app, including a later deployment, can decrypt captured payloads. OHTTP sent to NEAR's gateway is decrypted in the gateway itself ([routes/ohttp.rs L109–128](https://github.com/nearai/cloud-api/blob/d28dd0f1e7d455122963132224ceae95f961a474/crates/api/src/routes/ohttp.rs#L109-L128)).

### Why a client cannot fix this

`public-builds` requires the serving software and its keys to be authorized by named public release processes before a prompt is sent. Provider deployment instructions must not be able to substitute software ([serving-path requirements](../client/2026-10-09-design-assessment.md#serving-path-requirements)). Here the operator's token is the deciding authority, any ref is accepted, and a deployment can happen at any moment, including while a request is being served.

A client can authenticate the current action log and refuse instances running untagged refs. The operator can still deploy a different ref or an extra container immediately afterwards, and that software can read the TLS key and derive the signing keys. No check of one instance's quote, boot registers, compose file or GPU report bounds what the operator does next. For the same reason, the earlier client items — boot-register appraisal, compose constraints and detailed GPU appraisal — would not change the verdict and are not implemented.

Enabling public builds would need NEAR changes such as:

- Deploy only artifacts from a named, signed release workflow, and verify image provenance before running them.
- Bind key derivation to the deployed workload, so a different deployment cannot obtain the keys.
- Freeze the workload for the lifetime of the quoted serving keys, or rotate them and re-attest on every deployment.

## Chutes-backed models

DeepSeek-V3.2, Kimi K2.6 and other attestation-declared Chutes models are reached only through NEAR's gateway. The gateway builds the Chutes ML-KEM request from the plaintext JSON it receives ([cloud-api `d28dd0f`, `chutes/mod.rs` L542](https://github.com/nearai/cloud-api/blob/d28dd0f1e7d455122963132224ceae95f961a474/crates/inference_providers/src/attested/chutes/mod.rs#L542)). It rejects client-side end-to-end encryption for Chutes ([`supports_client_e2ee`, L1784](https://github.com/nearai/cloud-api/blob/d28dd0f1e7d455122963132224ceae95f961a474/crates/inference_providers/src/attested/chutes/mod.rs#L1784)). The gateway is therefore a plaintext recipient. Every gateway instance we sampled failed the required `UpToDate` CPU check ([evidence](near-gateway-evidence.json)). A client cannot bypass the gateway with NEAR credentials, so these models are excluded until NEAR offers a client-to-Chutes encrypted path.

On 2026-10-07, Kimi K3's report endpoint returned 503 because all Chutes instances failed NEAR's measurement pinning; NEAR fails closed there.

## Other models

The remaining NEAR catalog models declare no TEE ([discovery](https://github.com/ariofrio/pi-tee/blob/fa5e1547d4a99a8f40b0279f08aa24f9bcaa03b9/README.md#model-discovery)). They are hidden by default and cannot be admitted under any attested policy.

## What still works

`PI_NEARAI_POLICY=sdk PI_NEARAI_ROUTE=direct` selects `z-ai/glm-5.3-flash`. It verifies fresh Intel evidence, requires NVIDIA GPU evidence, checks the quote-bound TLS key on one connection, encrypts inference and verifies the response signature before showing text or running tools. It passed login, completion, tools, reasoning, usage and cancellation. [Adapter](https://github.com/ariofrio/pi-tee/blob/fa5e1547d4a99a8f40b0279f08aa24f9bcaa03b9/packages/nearai/src/direct.ts), [validation](direct-access.md#near-direct-route-and-evidence). Under `sdk` policy, the user accepts NEAR's operator as part of the trust set.

Written by Codex and Claude.
