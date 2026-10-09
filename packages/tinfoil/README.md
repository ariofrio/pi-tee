# pi-tinfoil

Tinfoil extension for Pi 1.0.4: native `/login tinfoil`, `TINFOIL_API_KEY`, live chat/tool discovery, thinking controls, tools/usage and EHBP encryption. Build in the locked Node 24 workspace and load `dist/extension.js` with `pi -e`. It depends on `pi-tee-core` and does not load NEAR's SDK. Stored credentials take precedence over environment keys; browser OAuth is not implemented. Packages remain unpublished.

## Policy and direct workers

Both providers use `PI_TEE_POLICY`, defaulting to `public-builds,egress=metadata`. Qualified direct workers supply A1/H1/G1/X2/B3/S3: the client verifies fresh CPU evidence, public guest/workload/container/runtime/key-custody chains, every CPU-bound GPU, authenticated serving count, firmware floors and protected mode. Compatible releases from named public repositories and hosted workflows need no maintained deployment pins. Public-code admission currently covers Gemma 4 31B, DeepSeek V4.1 Flash and GLM-5.3 when the catalog and available workers qualify. [Security model](../../docs/security-model.md), [serving contract](../../docs/tinfoil-public-profile.md).

Genoa workers below local CPU floors rate H2 and require `public-builds-trust-host,egress=metadata,host=outdated-firmware,gpu=verified` or weaker thresholds. They still need signed publisher minima, revocation checks, fresh nonce/key binding and a non-debug, non-migratable VMPL0 production guest. **Intel `OutOfDate` TDX workers are skipped under every policy**, because the pinned Go verifier rejects them during authentication. Availability can therefore be stricter than a policy threshold.

A single GPU requires SPT; multiple Blackwell GPUs require MPT for G1. G2 permits authenticated firmware below local floors, Hopper PPCIe with unattested NVSwitches, or nonce-only CPU association only when complete serving coverage and fresh evidence remain established. `verifier=local` uses the packaged NVIDIA verifier; `verifier=nras` authenticates all signed device/overall tokens and applies the same G checks, adding NVIDIA service trust and availability. `gpu=unchecked` skips GPU appraisal and rates G3; NRAS then warns that it has no effect.

No setup is required. The CPU helper ships in this package; NVIDIA's hash-checked WebAssembly verifier ships in `pi-tee-core`. Both run in cancellable workers under Node and Bun. The CPU helper has no file system/network; the local GPU bridge can reach only NVIDIA reference and OCSP services. Neither receives prompts or API keys. Authenticated immutable artifacts are cached, while CPU evidence, keys and admission freshness are checked for each request. [Build and runtime boundary](../../tools/nvidia-verifier/README.md).

Direct transport checks the attested key on the actual TLS 1.3 socket before credentials or EHBP ciphertext, sends once, rejects reconnect/resend, and uses a fresh encrypted cache salt. Admission expiry and policy epoch are checked after payload hooks. Named publishers remain trusted for safe releases and correct measurements; B3/S3 supplies no independent reproduction or per-release review.

## Billing gateway

When no direct worker qualifies, DeepSeek V4.1 Flash and GLM-5.3 can use `inference-gateway.tinfoil.sh`. The client fetches worker evidence through its nonce relay and runs the same direct appraisal. Successful checks establish the same A/H/G/X/B/S levels. Direct is preferred because fewer parties receive the API key and metadata. The live gateway [catalog](https://inference-gateway.tinfoil.sh/catalog) supplies routing hints, never keys or software authority; Gemma is excluded.

Gateway TLS uses WebPKI and ends at an unattested billing host. That host receives the API key, model and headers, including the worker hostname. This is disclosed in `/tinfoil status` and does not change an axis level: request and response bodies remain encrypted to the appraised worker's own HPKE key. `X-Tinfoil-Seal` names that worker; another worker cannot decrypt the body or authenticate a substituted response. [Protocol and validation](../../docs/tinfoil-gateway.md).

EHBP authenticates individual response frames but has no authenticated end-of-stream marker. The gateway can truncate a response at a frame boundary; Pi's SSE `finish_reason` check detects an unfinished completion, but trailing usage can disappear silently. EHBP also has no anti-replay: the gateway can replay the sealed request to the same worker, causing duplicate inference and billing, and return an equally authentic duplicate response. Client send-once cannot prevent this; plaintext reaches no new recipient. `/tinfoil status` discloses both limits separately from the axes.

A 412 means the sealed worker is unavailable. It fails that dispatch without re-appraisal, resend or an automatic loop. A later request performs fresh selection, appraisal and sealing under the same policy. Errors, redirects and dropped responses also fail without resending. Gateway and direct share bounded authenticated response streams and close-safe HTTP framing under Node and Bun.

## Router and reporting

The router is A3/H3/G3/X3, including hidden workers and sidecars. Its own CPU evidence has no client nonce; AMD revocation and local floors are unchecked. Signed repository tags supply B4 for that component, but the client cannot establish the complete plaintext code/runtime chain. Worker GPUs are unchecked and web-search/sidecar paths can carry plaintext. It therefore needs `trust-provider-and-host`. The pinned SDK re-attests and resends the same guarded request once only on an EHBP key-configuration mismatch. A second mismatch or any other request error fails; Pi adds no retry. Router preflight currently fails in Bun-compiled Pi because the SDK cannot dynamically load its Sigstore module, also reproduced on main; standalone Bun and Node attest successfully. [Live validation](../../docs/implementation.md#security-model-validation).

Each request appraises candidate routes that could meet the policy and selects by code, host, GPU, then egress. Another route may be selected only if it independently qualifies; verification failures never relax thresholds. `/tinfoil status` shows position, actual trusts/gaps, observed details, unavailable-verifier limits and selection reasons. Tinfoil handling commitments have not been reviewed and do not gate admission.

`PI_TINFOIL_POLICY` and `PI_TINFOIL_ROUTE` are removed with migration errors. Removed `sdk` maps to `trust-provider-and-host`; `approved` points to pinned review, which is not yet supported. `/tinfoil policy <position>[,axis=value…]` changes only Tinfoil’s policy, aborts its active requests and does not persist changes. `/tinfoil models refresh` forces catalog refresh; `PI_TEE_OFFLINE=1` restores snapshots without startup discovery. Other Pi providers, tools and extensions can access conversation plaintext; whole-session protection and independent approval remain unestablished. [Validation](../../README.md#validation).

Written by Codex.
