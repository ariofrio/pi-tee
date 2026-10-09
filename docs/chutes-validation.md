# Chutes validation

Validated 2026-10-09 with Pi 1.0.4, Node 24.21.0 and Bun 1.3.13. The adapter implements the approved A3/H1-or-H2/G3/X3 route and the parent-approved credential/metadata exception: ordinary WebPKI TLS receives the API key and disclosed metadata, while all request content is sealed to the per-request attested instance key. [Exact fields, trusts and limits](../packages/chutes/README.md).

## Live Pi

The capped synthetic Pi suite passed on `Qwen/Qwen3.6-27B-TEE` under both runtimes with `trust-provider-and-host,host=current`: native secret login, catalog, completion and usage, stored-key precedence, Unicode tool execution and result follow-up, reasoning, and RPC cancellation. [Node results](validation/chutes/node-live-pi.txt), [Bun results](validation/chutes/bun-live-pi.txt), [harness](../scripts/live-pi.ts).

Initial Qwen3.8 Node calls passed completion, tools and reasoning but its cancellation request failed during attestation. Initial Bun testing exposed unavailable native ChaCha20-Poly1305; the adapter now uses pinned portable crypto, tested against an independent Node/OpenSSL peer. An initial Qwen3.6 Bun tool request was rejected, then the unchanged request passed on the subsequent run. These live availability failures did not trigger a resend or weaker route. The completed suites above used the portable cipher and the explicit response-reader cancellation fix.

Credentials came from the caller's private Chutes dotenv file, loaded into each command only. No key, invocation token, prompt, response or quote body is recorded here. No NRAS, publication, sign-up or external message was used.

## Per-model evidence

The attestation harness checked the complete tool-capable confidential catalog returned in each sample: 12 models under Node and 12 under Bun. It sent discovery/evidence requests only, with no inference. Successful rows authenticate a selected instance's fresh client nonce, ML-KEM key, host SPKI/envelope and Intel quote/collateral locally, then apply the shared TDX floors. [Node observations](validation/chutes/node-attestation.json), [Bun observations](validation/chutes/bun-attestation.json), [harness](../scripts/live-chutes-attestation.ts).

| Model | Node sample | Bun sample |
| --- | --- | --- |
| `Qwen/Qwen3.5-397B-A17B-TEE` | A3/H1/G3/X3 | A3/H1/G3/X3 |
| `google/gemma-4-31B-turbo-TEE` | A3/H1/G3/X3 | A3/H1/G3/X3 |
| `deepseek-ai/DeepSeek-V3.2-TEE` | A3/H1/G3/X3 | A3/H1/G3/X3 |
| `Qwen/Qwen3.8-27B-TEE` | Rejected: no qualifying evidence | A3/H1/G3/X3 |
| `Qwen/Qwen3.6-27B-TEE` | A3/H1/G3/X3 | A3/H1/G3/X3 |
| `zai-org/GLM-5.1-TEE` | A3/H1/G3/X3 | A3/H1/G3/X3 |
| `moonshotai/Kimi-K2.6-TEE` | A3/H1/G3/X3 | A3/H1/G3/X3 |
| `deepseek-ai/DeepSeek-V4-Flash-0731-TEE` | A3/H1/G3/X3 | A3/H1/G3/X3 |
| `zai-org/GLM-5.2-TEE` | A3/H1/G3/X3 | A3/H1/G3/X3 |
| `moonshotai/Kimi-K3-TEE` | A3/H1/G3/X3 | A3/H1/G3/X3 |
| `Qwen/Qwen3-32B-TEE` | A3/H1/G3/X3 | A3/H1/G3/X3 |
| `Qwen/Qwen3-235B-A22B-Thinking-2507-TEE` | Rejected: no qualifying evidence | Rejected: no qualifying evidence |

Rejection does not assign H3 or authenticate a lower route. The samples establish neither permanent model ratings nor the properties of future instances. Every inference performs its own appraisal. Source and catalogs never upgrade A/G/X.

## Local verification

The native provider/network tests cover wrong nonce, swapped key, stale discovery, dispatch after evidence expiry, below-floor H2 rejection/admission, an instance outside the matching evidence set, no plaintext content at the API hop, encrypted prompt/tools/reasoning, response corruption/replay/plaintext/truncation, no resend, and cancellation after an authenticated text delta. Synthetic CPU verifier results test dispatch enforcement, not deployment qualification. [Provider tests](../tests/chutes-provider.test.ts), [protocol tests](../tests/chutes-crypto.test.ts).

Saved private evidence from the research probe passes real Intel signature/collateral verification and host-envelope/nonce/key tests under Node and Bun; corrupted keys, nonces, certificates, signatures and quotes fail. Set `CHUTES_TEST_EVIDENCE_DIR` to run these; CI skips the private fixture. [Evidence tests](../tests/chutes-evidence.test.ts), [research and pinned source](provider-ratings-verification.md#chutes).

The shared first commit extracts TDX SVN and collateral-edition floors into `rateAuthenticatedTdxHost()`, reusing NEAR's existing calculation and preserving Tinfoil's policy values/digest. Provider behavior stays in `packages/chutes`; no common policy or transport exception was added. [Core floors](../packages/core/src/tdx-host.ts).

## Limits

TDX v4 is the only offered CPU format; SNP and other quote formats fail closed. The client cannot authenticate provider-controlled software, exclusive key custody, the complete plaintext/GPU serving closure, or egress/storage restrictions. Those gaps remain A3/G3/X3, with provider and host trust. Numeric API billing metadata and encrypted stream ordering are not enclave-authenticated. The full Pi suite samples one model per runtime; the remaining rows are evidence-only checks.

Written by Codex.
