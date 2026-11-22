# NEAR KMS provenance and the November 2026 incidents

Observed 2026-11-22 11:43–11:52 UTC from macOS on Node 26.10.0, client [c1418ff](https://github.com/ariofrio/pi-tee/commit/c1418ff), `@nearai/inference-sdk` 0.1.0 and `@phala/dcap-qvl` 0.6.3. Two incident reports prompted this record:

- [Phala's preliminary report](https://phala.com/posts/phala-november-preliminary-incident-report) (2026-11-10) describes attacker-created CVMs, possibly exposed secrets derived from Phala's KMS, and a KMS root-key rotation on 2026-11-06. It also describes a compromised DeepSeek V4 Flash 0731 inference VM that exposed request data from 2026-10-21 to 2026-11-08. A Phala cofounder [attributed the KMS exposure](https://news.ycombinator.com/item?id=50598304) to a bug in the KMS replication policy that let a fake replica obtain key material.
- [NEAR's report](https://near.ai/blog/security-incident-report-sglang-vulnerability) (2026-11-09) describes an SGLang remote-code-execution vulnerability. It gave an attacker code execution on one inference server, and on 2026-11-08 the attacker could have observed requests being processed there, including confidential ones.

The question was whether NEAR's private inference depends on Phala's KMS, and whether either incident changes the NEAR ratings. This record compares the October fixtures with today's evidence and with Base chain state.

## Scope and method

- **NEAR direct.** The six discovered direct endpoints, which serve DeepSeek V4.1 Flash 1017 and its abliterated variant, GLM-5.3 Flash, Qwen3.6-35B and Qwen3.8-27B and its abliterated variant. Each was fetched over the [direct channel](../../../packages/nearai/src/direct-channel.ts) with a fresh nonce. The [NEAR CPU verifier](../../../packages/nearai/src/cpu.ts) verified each quote as Intel `UpToDate` at H1.
- **NEAR gateway.** `GET /v1/attestation/report` for GLM-5.3 Flash, DeepSeek V4.1 Flash 1017 and Qwen3.8-27B, with the API key and a fresh nonce. The gateway and all six distinct model CVMs verified `UpToDate`, debug off and H1, and each report bound its request's nonce.
- **Authenticated fields.** For every CVM, the RTMR3 event log was replayed and matched the verified quote's RTMR3, with every runtime event's digest recomputed from its name and payload. So `app-id`, `compose-hash`, `instance-id`, `os-image-hash`, `key-provider` and `mr-kms` below are bound to verified quotes. The same replay matches both October fixtures. pi-tee itself does not replay RTMR3 for NEAR, and these fields do not affect admission.
- **On-chain state.** Public `eth_call` and `eth_getStorageAt` on Base (chain 8453) and Ethereum through public RPCs. Historical reads use blocks found by timestamp, and each reported time is that block's timestamp.
- **Phala Cloud's KMS list.** The public `GET https://cloud-api.phala.network/api/v1/kms`.
- **Not done.** No inference, NRAS, KMS RPC or management interface. Third-party pins are cited as corroboration, not as authority.

The raw captures are kept privately in the investigating thread's storage as `near-direct-2026-11-22.json` (SHA-256 `870c3bafb51ee885…2d019035`) and `near-gateway-2026-11-22.json` (SHA-256 `b3c31e5c7f74bfab…4cedc72b2f`). Neither is committed.

## Observations

### Which KMS provisions NEAR's CVMs

In dstack, the `key-provider` event's `id` is the DER public key of the KMS root CA that issued the CVM's keys ([`request_app_keys_from_kms`, L2466–2489](https://github.com/Dstack-TEE/dstack/blob/c87303818753e7abb3233bd1f5a4b611cb981154/dstack/dstack-util/src/system_setup.rs#L2466-L2489)). `mr-kms` is that KMS's own aggregated measurement ([dstack#135](https://github.com/Dstack-TEE/dstack/pull/135)).

| Evidence | 2026-10-07/09 fixtures | 2026-11-22 |
| --- | --- | --- |
| Model app ID | `2c0a0c96…f91b` (GLM, [fixture](../../../tests/fixtures/near-glm-direct-attestation.json)) | `2c0a0c96…f91b` on all six model CVMs |
| Gateway app ID | `f550fdfb…31ae` ([fixture](../../../tests/fixtures/near-gateway-attestation.json)) | `f550fdfb…31ae` |
| KMS root CA (`key-provider` id) | P-256 `04394aae…b6c11682`, model and gateway | The same key on all seven CVMs |
| `mr-kms` | `a1fc1360…e641` (dstack-nvidia 0.5.11 image); none on the 0.5.4 gateway | `22a6652c…bc56` on all seven CVMs (dstack-nvidia 0.5.15, `os_image_hash` `3bb7d262…4ef2`; gateway `8db40cb2…15bd`) |
| `key_provider_id` pin in `app_compose` | Empty | Not pinned |

The KMS CA `04394aae…` matches none of Phala's KMS roots:

| KMS | CA key | Source |
| --- | --- | --- |
| Phala "Phala KMS 2026-11" | `04e8e325…44ee` | Phala Cloud KMS list |
| Phala Base KMS `0x2f83172A…Ba9C` | `048bf84f…425f` | KMS list and contract `kmsInfo()` |
| Phala Ethereum KMS `0xd343a3f5…5a80` | `04daad2c…2710` | KMS list and contract `kmsInfo()` |
| Phala Cloud's pre-2026-11 KMS | `048844eb…9d9f` | No longer listed. [TxnLab's pin](https://github.com/TxnLab/zerosignal/blob/c821aaf9e2/go/attest/compose.go#L725-L740) records it from 2026-08 and 2026-10 Phala CVMs. [teep's 2026-09-10 testdata](https://github.com/13rac1/teep/tree/d9f59d839eb887b50f5afd234e192eac5ec45a2d/internal/integration/testdata) shows it on NanoGPT, which routes through Phala; NEAR responses in the same testdata carry only `0439…` and `0228…` |

Neither NEAR app is registered in Phala's KMSs. On Phala's Base KMS, `registeredApps()` is false for the model app at every sampled block from 2026-05-02 to 2026-11-22, and for the gateway app on 2026-11-22. Neither address has code on Ethereum, and Phala's Ethereum KMS registers neither.

### Who governs it

NEAR's apps are `DstackApp` proxies on Base. They are registered in the `DstackKms` proxy `0x8fa1593f…d637`. A May 2026 third-party trace identified that proxy as the contract of NEAR's KMS at `kms.cvm1.near.ai` ([trust-chain analysis](https://github.com/amiller/devproof-audits-guide/blob/43e938f32d21111306e3c4dfd0e2f9201dcc952b/case-studies/near-ai-private-inference/TRUST-CHAIN-ANALYSIS.md)). On 2026-11-22:

- **Compose hashes.** `allowedComposeHashes` is true for all five model compose hashes and the gateway's. `allowAnyDevice` is true on both apps.
- **OS images.** NEAR's `DstackKms` allows both current OS images. It removed the October 0.5.11 image (`a6eafc5f…`) at block 55200078, 2026-11-09 13:19:51 UTC ([tx `e03d0ce9…`](https://basescan.org/tx/0xe03d0ce991e81a500dc0000a22eb97458e3011e70a27471a23bf8917336a8f71)). It added `3bb7d262…` by block 58361826 (2026-11-16 20:59 UTC).
- **KMS measurements.** `kmsAllowedAggregatedMrs` is true for both observed `mr-kms` values. `a1fc1360…` became true by 2026-09-02 15:22 UTC and `22a6652c…` by 2026-10-21 04:48 UTC. Phala's Base KMS allows neither. In the [reference contract](https://github.com/Dstack-TEE/dstack/blob/c87303818753e7abb3233bd1f5a4b611cb981154/dstack/kms/auth-eth/contracts/test-utils/reference/v0.6.0/DstackKmsV060.sol#L256-L307), this mapping gates which KMS instances may receive the root keys, and `isAppAllowed` gates app boots on registration, OS image and the app's own policy. The deployed implementation `0x2e99ade1…2e28` was not source-verified here.
- **Owner.** Both apps and the `DstackKms` share one owner, an address without code. The owner was `0x21e6b7eF…AB8d` until 2026-11-11. `transferOwnership` then moved the KMS to `0x3CE41427…Dcdb` at 21:49:41 UTC ([tx `577aca44…`](https://basescan.org/tx/0x577aca44cd98b69a24191fab13c22227062c52ba7671118eeaf1638b023c3dc0)), and the model app at 22:15:14 UTC ([tx `25364f45…`](https://basescan.org/tx/0x25364f450489ca3b4255d701d28658be2323af9b946adbc973b32c3f0f0ff54f)). Phala's Base KMS has a different owner, `0x3926658a…a663`.
- **`kmsInfo()`.** It names CA `04228f80…bcbc`, not `0439…`. Third-party captures from May and teep's September testdata show that earlier NEAR root on NEAR CVMs. The chain does not say which KMS instance holds `0439…`.

### Keys before and after 2026-11-06 and 2026-11-08

| KMS-derived key | October fixture | 2026-11-22 |
| --- | --- | --- |
| GLM-5.3 Flash Ed25519 response signer | `5a0210f2…` | `5a0210f2…`, unchanged, on all three CVMs the gateway lists for GLM |
| GLM-5.3 Flash model OHTTP key config | `010020da8c5a…` | `010020da8c5a…`, unchanged |
| Gateway Ed25519 signer | `40599fb2…` | `40599fb2…`, unchanged |
| Gateway OHTTP key config | `010020e4e354…` | `010020e4e354…`, unchanged |

These keys derive from the app's KMS root and a fixed path ([`signing.rs` L149–176](https://github.com/nearai/inference-proxy/blob/0f37728af5387d4805a12db133662d769a679373/src/signing.rs#L149-L176)). Their stability is consistent with the unchanged app ID and KMS root.

The attested compose-manager action logs on three GLM-serving CVMs record `prod/rotate-compose-manager-token.yaml` at 2026-11-10 00:35–00:39 UTC. That file replaces compose-manager's deployment bearer token without restarting the CVM ([v0.0.554 file](https://github.com/nearai/cvm-compose-files/blob/fe7493ee3a0b3d36c1079c095de554e7b218da5c/prod/rotate-compose-manager-token.yaml)). It rotates the operator credential, not KMS-derived keys.

### SGLang containers' access

NEAR does not say which server or compose was compromised. In the GLM-5.3 Flash pack before the incident ([`132912c`](https://github.com/nearai/cvm-compose-files/blob/132912c5a119d6011e73c98ec2b23f806c2411cc/prod/GLM-5.3-Flash-SGL-TP2x4-W4AFP8-V12Q8.yaml)), the SGLang engines and the inference proxy have different access:

- **SGLang engines.** They mount no `dstack.sock` or Docker socket and are not `privileged`. They share `ipc: host` and the default Compose network with the proxy.
- **Inference proxy.** It is `privileged`, mounts `/var/run/dstack.sock`, decrypts E2EE/OHTTP, and forwards plaintext to the engines over HTTP.

After the incident, NEAR added admin authentication and credential redaction to its SGLang build ([`ab7eeee`](https://github.com/nearai/cvm-compose-files/commit/ab7eeee2e3), 2026-11-10). That commit says the compose files stay on the earlier engine image. Which change fixed the exploited bug is not public.

### DeepSeek V4 Flash 0731

- **Phala's affected deployment.** Phala says it served this model only through the affected route. The [OpenRouter announcement](https://openrouter.ai/blog/announcements/data-processing-incidents-on-inference-providers/) lists Phala's report.
- **Chutes.** Its public chute API lists `deepseek-ai/DeepSeek-V4-Flash-0731-TEE` (chute `b4d58772-e72b-55d1-9d73-d30dff6d2ed8`) under user `chutes`, with image `sglang` 0.5.17, created 2026-08-01. pi-tee appraises its instances through Chutes' own [sek8s evidence](../../../packages/chutes/src/evidence.ts), not dstack.
- **NEAR.** Its catalog lists no 0731 model today.

## Conclusions

- **NEAR does not use Phala's KMS.** Every NEAR CVM sampled, in October and today, takes keys from the KMS root `04394aae…`. It is none of Phala's four KMS roots, and it did not change across Phala's 2026-11-06 rotation. The measured KMS build and NEAR's app policies are authorized in NEAR's Base contracts, which Phala's contracts do not reference. The serving KMS instance's operator is not shown by the chain. Its name, `kms.cvm1.near.ai`, comes only from the May third-party trace.
- **No public evidence places NEAR in the scope of Phala's incident.** The NEAR app IDs, KMS root and KMS-derived keys are unchanged. Phala's report names one tenant and one model route, neither identified as NEAR.
- **NEAR's SGLang incident was inside the attested closure.** SGLang is an authorized container in the measured, compose-manager-deployed workload. It receives plaintext from the proxy by design. NEAR's report says the attacker could observe confidential requests on that server.
- **Whether the SGLang compromise reached KMS-derived keys is unknown.** NEAR's report says nothing either way. In the GLM pack, getting keys from an SGLang container requires a further step, such as a container escape or reaching the privileged proxy or compose-manager. The report says the attacker went on from the server to NEAR's infrastructure.
- **The app-wide keys were not rotated.** If any of them was obtained, it still decrypts captured E2EE/OHTTP payloads and signs valid responses for every CVM of the app. A client cannot detect that. The [runtime/KMS investigation](runtime-key-custody.md) already counts every workload in the app as a key holder.
- **Ratings.** The A3/H1–H2/G3/X3 levels remain accurate. Neither incident changes code authority, fresh CPU evidence (H1 today), GPU coverage or egress.
- **No new admission check.** The required `trust-provider-and-host` policy already trusts NEAR's operator. The operator controls compose hashes, OS images and KMS replication through a single-owner contract, so pinning the KMS root, app ID or `mr-kms` would not bound what it can deploy. A pin would not detect a fake replica holding the real root, which is the failure Phala described, or a compromised workload inside the closure, which is NEAR's incident. It would also break on the rotation one would want after such a compromise.

## Unknowns

- **The `0439…` KMS instance.** Which instance, operated by whom, holds `0439…`, and why `kmsInfo()` still names `0228…`. Whether NEAR still runs a `0228…` KMS.
- **The deployed KMS build.** Whether the build NEAR authorized on 2026-10-21 (`22a6652c…`) shares the replication-policy bug Phala described. Phala has withheld exploit details. dstack's KMS onboarding and launch-ticket changes from 2026-11-14 onward postdate that authorization.
- **The compromised server.** Which NEAR server, compose and SGLang image was compromised. Whether the attacker reached `dstack.sock`, the proxy, compose-manager or the TLS key.
- **Venice and RedPill.** Whether Venice or RedPill routes reached Phala's DeepSeek V4 Flash 0731 deployment. Phala's statement that it served the model only through the affected route suggests not.

No credential, prompt, response or raw quote is recorded here, and NRAS was not contacted.
