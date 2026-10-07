# pi-tee

**Work in progress.** Approved-workload enforcement is not implemented; Approved mode blocks all inference. Live Pi inference validation remains incomplete; see [Validation](#validation). SDK mode is an explicit opt-in with the trust limits below.

Two provider extensions and one shared library, built together in this repository:

| Package | Purpose |
| --- | --- |
| [pi-nearai](packages/nearai/README.md) | NEAR AI login, model discovery, attested gateway/model SDK transport, encryption, and response-signature verification. |
| [pi-tinfoil](packages/tinfoil/README.md) | Tinfoil login, model discovery, SDK verification, and EHBP encrypted transport. |
| [pi-tee-core](packages/core/README.md) | Shared policy, native catalog publications, request guards, response buffering, and terminal error handling. |

Installing one provider does not load the other provider's SDK. The shared library is not a Pi extension. Both provider extensions can run together and have separate commands and credentials.

This initial implementation provides **SDK-policy integrations**. The default `approved` policy blocks inference and hides models from the picker because **no independently approved production deployment profile is implemented**. Selecting `sdk` explicitly accepts the additional authorities described in each provider's report. It does not satisfy the manufacturer-only/closed-trust-set objective. There is no automatic downgrade.

## Run the local build

Use Node 24 and Pi 1.0.4. Tinfoil can also run on Node 22.19 or later; NEAR's SDK requires Node 24. NEAR refuses Bun and probes the required TLS APIs. Neither package has been published to a registry. The provider SDK and Pi versions are exact pins, but SDK transitive ranges are frozen only by the repository lockfile. Use this locked checkout for the tested dependency set; a fresh tarball install can resolve newer transitive packages and is not verifier qualification.

```sh
npm ci --ignore-scripts
npm run check
```

Start the compiled entries from the locked checkout:

```sh
PI_NEARAI_POLICY=sdk PI_TINFOIL_POLICY=sdk \
  node_modules/.bin/pi \
  -e packages/nearai/dist/extension.js \
  -e packages/tinfoil/dist/extension.js
```

Then use Pi's native secret prompts:

```text
/login nearai
/login tinfoil
```

Credentials live in Pi's normal credential store. `NEARAI_API_KEY` and `TINFOIL_API_KEY` are also supported. Stored credentials take precedence over environment keys. `/logout` uses Pi's native flow. Browser OAuth is not implemented: these are API-key logins.

The `PI_*_POLICY` variables select `approved` or `sdk`; omitted means `approved`, and unknown values reject extension loading. In-session commands can select either policy without persisting it:

```text
/nearai status
/nearai models
/nearai models tee
/nearai models all
/nearai models refresh
/nearai policy sdk
/nearai policy approved

/tinfoil status
/tinfoil models
/tinfoil models refresh
/tinfoil policy sdk
/tinfoil policy approved
```

Changing policy aborts in-flight requests and updates model availability. A status report always states that independent approval, a closed trust set, and protected-session enforcement are not established in this release. Footers apply only to the selected provider. No prompts, credentials, completions, or quote bodies are written to ordinary logs.

## Discovery and request behavior

Model discovery uses each provider's public `/v1/models` endpoint. It selects chat models advertising tool support, maps input modalities, context/output limits, reasoning controls where declared, and prices. NEAR additionally looks up public `/v1/model/{id}` metadata, with four concurrent requests, a three-second per-model timeout and a 64 KiB body limit within the overall discovery deadline. Only matching model metadata declaring `providerType: "vllm"` and `attestationSupported: true` is classified as TEE-capable. Missing, failed, mismatched and malformed metadata is unknown. This follows the SDK's model-evidence selection rule; it is not cryptographic verification.

NEAR defaults to **TEE-only discovery**, hiding non-TEE and unknown models even in SDK mode. Set `PI_NEARAI_MODEL_VISIBILITY=all` at startup or run `/nearai models all` to show them; `/nearai models tee` restores the filter. In-session visibility is not persisted. Show-all labels non-TEE/unknown entries as inference-blocked and does not relax the model-attestation requirement. Their inference requests fail before SDK setup. Older stored catalogs without capability metadata stay hidden until refreshed or explicitly shown as unknown. The status report distinguishes the total catalog from `declaredTeeModels` and reports `modelVisibility`.

The visibility filter is separate from **Approved policy**, which still hides all models from Pi's picker until a deployment has independent approval, regardless of visibility. Tinfoil's catalog serves its confidential-inference provider; no additional non-TEE catalog mode is implemented there. Metadata and billing remain provider claims; models that lack qualifying SDK evidence can still fail before inference. Missing price metadata is labeled, rather than presented as a known free service. NEAR's ordinary pricing tiers beyond the base costs are not modeled.

The async extension factory attempts bounded startup discovery so first-run `--list-models` works. Pi's native `refreshModels`, stored catalog, and generation-checked publication APIs then provide cache restoration, forced refresh, and four-hour freshness checks. No refresh timer or separate catalog database exists. Failed refresh preserves valid cached models. Set `PI_TEE_OFFLINE=1` to skip startup network discovery and use the native stored snapshot. `pi update --models` does not load extensions; use the provider refresh commands. Startup discovery is performed on each online load, even when a native stored snapshot exists.

All inference requests go through a final serialized-body guard after Pi's payload hooks. It fixes the endpoint and canonical model, ignores caller transport/header overrides, restricts supported fields, accepts only function tools, and rejects remote media URLs. Images must be supported inline data. Hosted search/execution tools, file URLs, audio/video, and unclassified options are rejected.

The extensions reuse Pi's OpenAI conversion, tool handling, reasoning output, usage/cost accounting, instrumentation, and cancellation. Provider retries are forced to zero. Security and ambiguous-execution failures use fixed terminal errors that do not trigger Pi 1.0.4's turn/summarization retry classifier. This compatibility rule must be rechecked on a Pi upgrade.

NEAR responses are buffered in memory until the SDK verifies their exact signed request/response record against a model attestation. No text or tool-call bytes are released before verification. Decrypted NEAR response bodies are capped at 8 MiB; gateway network responses are capped at 32 MiB before OHTTP decoding and the SDK's retained signature record. These are body-size limits, not a total process-memory budget: decoding and verification keep additional copies. Request bodies are capped at 16 MiB, catalog bodies at 2 MiB, and request duration at ten minutes or a shorter caller timeout. There is no plaintext disk spill. Buffering delays visible NEAR output until completion. Tinfoil streams through its authenticated encrypted transport; the SDK's internal key-rotation resend remains part of the explicit SDK-policy trust assumption.

## Security scope and remaining gates

These extensions guard requests sent through their own registered providers. They **do not protect an entire Pi conversation** from model switches, virtual-model fallback, compaction through another provider, other extensions, or external tools. All local plaintext-accessing code remains trusted. Avoid registering another extension under the same provider ID: registration can replace the provider implementation.

The [security contract](SECURITY.md) lists the outstanding production requirements. The [assessment/design](docs/design.md) describes the intended approved-worker transport and server contracts. In particular:

- Tinfoil Approved workloads must bypass `SecureClient.fetch` automatic recovery, pin code and hardware references, appraise revocation/security floors, and prove the direct worker or enforced forwarding chain and GPU path.
- NEAR needs a serving-session binding and enforced runtime/key/forwarding closure. A shared certificate, shared model signer, public source, or another preflight quote is insufficient.
- Session-wide protection needs a demonstrated guard after Pi resolves the physical provider, including summaries and fallback.
- Actual deployment approval requires an independent artifact/key/dependency inventory, source/rebuild review, live end-to-end validation, and an independent verifier/transport review.

No manifest, environment flag, or successful SDK check can enable an Approved production profile in this release. The exact production closed trust inventory has not been established. Public releases permit review and monitoring; new releases need independent approval before a future Approved transport can use them.

## Validation

```sh
npm run check             # build, types, adversarial/provider tests
npm run smoke             # compiled entries through Pi's real loader and synthetic native login
npm run smoke:packages    # isolated tarball installs/loader/login; may download dependencies
npm run smoke:catalogs    # public metadata only; no credential or inference
npm run smoke:attestation # live Tinfoil router SDK verification; no inference
npm run smoke:pi -- tinfoil # opt-in, billable Pi CLI/RPC tests; requires TINFOIL_API_KEY
```

The [live Pi harness](scripts/live-pi.ts) accepts `nearai` or `tinfoil` and an optional model ID. Supply the corresponding credential in the environment, or use Node's `--env-file` with a private dotenv file, for example `node --env-file=/path/to/private/tinfoil.env --import tsx scripts/live-pi.ts tinfoil`. It uses synthetic prompts, an isolated owner-only Pi credential store and project, a harmless Unicode echo tool, capped output tokens and a two-minute deadline per CLI invocation. It checks native secret login, discovery, completion/usage, stored-key precedence, tool execution and result follow-up, reasoning where declared, and RPC cancellation at a response-consumption barrier. `--cancel-only` runs just the cancellation check. It removes its temporary store and never prints credentials or provider payloads. A terminal inference failure stops subsequent checks; it is not a successful end-to-end result.

Tests exercise the real Pi OpenAI adapter with controlled external transport responses: payload/model/header/URL overrides, hosted-tool injection, both retry classifications, cancellation, policy changes, signature barriers, malformed/truncated streams, bounded buffering, Unicode tool arguments, usage, and catalog validation. These tests do not substitute for hardware evidence or a production security audit.

Observed on 2026-10-06: live discovery mapped 44 NEAR chat/tool models, with **3** matching declared model-attestation capability and shown by the default filter, plus 7 Tinfoil models. Tinfoil router evidence passed the pinned SDK verifier. These are point-in-time observations, not a claim about today's full fleet.

On 2026-10-07, Tinfoil's experimental direct route passed the complete actual Pi suite in one run with `gemma4-31b`: native secret login, stored-key precedence, completion/usage, Unicode tool execution/result follow-up, reasoning/final text and RPC cancellation. Enable it with `PI_TINFOIL_POLICY=sdk PI_TINFOIL_ROUTE=direct`; it exposes only the pinned Gemma worker. This route verifies the exact artifact and attested TLS socket and sends once, with no rotation resend. The default router route is unchanged. All **35 automated tests**, compiled-loader checks and isolated-package checks pass.

The cancellation harness uses a dedicated metadata pipe because Pi redirects extension stdout to stderr in RPC mode. A test-only one-second response-consumption barrier allows abort to reach a fast stream after HTTP 200. It validates local RPC cancellation and acknowledgement, not the remote engine's generation-stop timing. A separate router cancellation retry passed with `gpt-oss-120b`. Intermittent router SDK key-configuration mismatches remain unresolved; the direct route avoids that SDK resend path.

NEAR's gateway route remains blocked by its observed `OutOfDate` TDX status under the required `UpToDate` policy. Separate [direct-worker research](docs/direct-access.md) passed strict same-TLS GLM attestation and signed inference; Qwen's direct quote remained `OutOfDate`. Fresh Tinfoil v3 CPU evidence passed revocation/security appraisal, and its CPU-bound GPU evidence passed NVIDIA's local verifier and negative mutations. These stronger research checks are not yet integrated into the extension, and neither provider has an enabled Approved profile.

A fresh install reported the existing NEAR dependency chain's low-severity [elliptic signing advisory](https://github.com/advisories/GHSA-848j-6mx2-7j84), with no patched version. The locked DCAP adapter uses native Node verification; its browser fallback only verifies public-key signatures. No signing call was found in that adapter. This is an assessment of the used path, not an audit exemption or a claim that the dependency is vulnerability-free.

Written by Codex.
