# NEAR direct model discovery

NEAR direct discovers candidates from the [OpenAI catalog](https://cloud-api.near.ai/v1/models), [capability catalog](https://cloud-api.near.ai/v1/model/list), and [endpoint registry](https://completions.near.ai/endpoints). A candidate must have tools and text output in the OpenAI catalog, matching attestation declarations in model metadata, tools in the capability catalog, and an exact canonical model ID in the registry. Registry-only models and aliases are ignored, as required by the [SDK's direct endpoint guide](https://github.com/nearai/inference-sdk/blob/main/js/docs/verification-guide.md#use-a-direct-model-endpoint).

The [discovery adapter](../packages/nearai/src/discovery.ts) accepts only hostnames matching `^[a-z0-9-]+\.completions\.near\.ai$`, without schemes, ports, paths or nested subdomains. Capability-list pagination must be complete; failed or incomplete discovery offers no direct candidates. A catalog provider label does not exclude a direct candidate; direct protocol support must pass the actual SDK/evidence checks. Gateway-only discovery continues through its existing `vllm` metadata checks. Direct availability is kept per route in memory and does not overwrite the gateway’s `sdkTransportAvailable` flag or get persisted into catalog snapshots. Offline snapshots do not restore direct endpoint authority: fresh network discovery is needed to populate direct candidates.

Catalogs and the registry identify where to look. They establish no security levels. Before each prompt, the [direct adapter](../packages/nearai/src/direct.ts) fetches a fresh nonce-bound report on one WebPKI-authenticated TLS 1.3 socket, requires the report's model name to match the canonical model, authenticates Intel signatures and collateral, and binds the report's SPKI to that socket. Credentials and inference follow SPKI approval. The socket cannot reconnect or resend inference, and response signatures must verify before Pi receives completion or tool output.

H1 additionally requires Intel `UpToDate`, TDX SVN components at least `[3,1,2]`, and verified TCB/QE collateral editions at least 20. Fresh `OutOfDate`, below-floor or unreadable floor values are H2. Ratings use the weakest CPU evidence checked for the endpoint. Every NEAR route remains A3/G3/X3: runtime code is provider-controlled, complete GPU serving coverage is unestablished, and plaintext-handling limits are unverified. Optional local GPU diagnostics cannot raise G3, and no NEAR route calls NRAS. [Security model and trust disclosures](security-model.md).

The [provider](../packages/nearai/src/index.ts) appraises each discovered endpoint, skips unreachable or rejected ones, and selects the strongest endpoint whose observed levels satisfy the policy. `/nearai status` attaches endpoint skips to each request’s route decision, reports the selected hostname/model, actual levels and observations, or the strongest authenticated rejected levels and failing axis. Concurrent requests keep separate skip notes, and a request blocked at preflight clears prior route decisions. Channel `TEE_TLS_KEY_REJECTED` failures are distinguished from unreachable endpoints even when the SDK wraps the failure; raw diagnostic messages are never displayed. Discovery never relaxes policy. `trust-provider-and-host,host=current` rejects H2 Qwen instances before any prompt; `trust-provider-and-host,host=outdated-firmware` admits their A3/H2/G3/X3 evidence. Both positions disclose provider and host trust.

## Live validation, 2026-10-09

The complete live catalog contained 58 capability entries; the registry contained 22 endpoints. Their intersection produced these three tool-capable, attestation-declared direct models. All three passed fresh evidence appraisal without inference credentials:

| Model | Direct hostname | Observed levels | Intel status | TDX SVN / collateral editions |
| --- | --- | --- | --- | --- |
| `z-ai/glm-5.3-flash` | `glm-5-3-flash.completions.near.ai` | A3 H1 G3 X3 | `UpToDate` | `0b010400000000000000000000000000` / 20, 20 |
| `Qwen/Qwen3.6-35B-A3B-FP8` | `qwen3-6-35b.completions.near.ai` | A3 H2 G3 X3 | `OutOfDate` | `07010300000000000000000000000000` / 20, 20 |
| `Qwen/Qwen3.8-27B` | `qwen3-8-27b.completions.near.ai` | A3 H2 G3 X3 | `OutOfDate` | `07010300000000000000000000000000` / 20, 20 |

`Qwen/Qwen3-VL-30B-A3B-Instruct` declares attestation but no tools in either catalog, so it is excluded. The registry's other model names do not qualify through this catalog intersection. These are observations of sampled requests, not fleet-wide guarantees. Optional GPU detail appraisal did not establish authenticated device details during this run; G3 is unchanged.

The [live Pi suite](../scripts/live-pi.ts) supports `nearai <model> --direct`, asserts the picked direct route's actual levels, and prints Intel status through a metadata-only pipe. GLM uses `PI_TEE_POLICY=trust-provider-and-host,host=current`; Qwen uses `PI_TEE_POLICY=trust-provider-and-host,host=outdated-firmware`. Each credentialed run loads `~/.config/secrets/nearai` into that command only. The suite checks native secret login, catalog registration, stored-key precedence, completion/usage, Unicode tool execution and result follow-up, reasoning/final text, and RPC cancellation at its response-consumption barrier. It removes its isolated credential store and does not log provider payloads.

| Model | Node 24.21.0 / Pi 1.0.4 | Official compiled Bun Pi 1.0.4 |
| --- | --- | --- |
| GLM-5.3 Flash | Passed, A3 H1 G3 X3 | Passed, A3 H1 G3 X3 |
| Qwen3.6 35B A3B FP8 | Passed, A3 H2 G3 X3 | Passed, A3 H2 G3 X3 |

The compiled runtime is the official [Pi 1.0.4 macOS ARM64 release](https://github.com/earendil-works/pi/releases/tag/v1.0.4); its archive matched GitHub's SHA256 `717dcd38a03849e919f9dec9daa96f5ca102e15ea33d804e5db57b1d47e513bc`. Qwen3.8 received an evidence-only check, not the billable Pi suite.

[Provider/SDK-boundary tests](../tests/near-direct-discovery.test.ts) cover catalog/registry mismatches, hostile hostnames, no-tool models, below-floor policy rejection before prompt transmission, unreachable endpoint skipping/status, and report-model mismatch. Existing [CPU floor tests](../tests/near-cpu.test.ts), [socket tests](../tests/near-direct-channel.test.ts), and [local GPU/no-NRAS tests](../tests/near-gpu.test.ts) retain their checks. CI runs discovery under Node and Bun.

## GPU evidence smoke, 2026-10-10

[`npm run smoke:near-gpu [model]`](../scripts/live-near-gpu.ts) appraises CPU evidence with the direct route's Intel verifier and statuses, and requires GPU evidence and applies NVIDIA's local verifier and the default GPU policy. With no argument it checks the first discovered direct model. Intel statuses and TDX SVNs matched the table above under Intel's TCB info for FMSPC `90C06F000000` (edition 20, TCB date 2025-08-13; this copy issued 2026-10-10). The Qwen endpoints' TDX late-microcode SVN is 3; edition 20's `UpToDate` level requires 4. For all three models, NVIDIA's verifier accepted eight Hopper GPUs (result code 0) and the default policy rejected them with `TEE_GPU_POLICY_REJECTED`; the smoke reports that and exits 1. GLM reported driver `595.58.03` and both Qwen endpoints `570.172.08`, all with VBIOS `96.00.CF.00.02`.

Written by Codex.
