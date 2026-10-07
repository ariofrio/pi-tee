# pi-tee

NEAR AI and Tinfoil providers for Pi, with native API-key login, live model discovery, tools, usage accounting and encrypted inference.

**Work in progress.** Default `approved` mode hides models and blocks inference because this release enables no independently approved production profile. `sdk` mode explicitly accepts each route's reported trust assumptions; it does not establish a manufacturer-only trust set.

| Package | Purpose |
| --- | --- |
| [pi-nearai](packages/nearai/README.md) | NEAR AI provider, encryption and response-signature verification. |
| [pi-tinfoil](packages/tinfoil/README.md) | Tinfoil provider, attestation and encrypted HTTP bodies (EHBP). |
| [pi-tee-core](packages/core/README.md) | Shared policy, catalog refresh, request guards and response authentication. |

The providers can run together with separate credentials and commands. Each loads only its own SDK; the shared library is not a Pi extension.

## Run the local build

Use Node 24 and Pi 1.0.4. Tinfoil also supports Node 22.19 or later; NEAR requires Node 24 and rejects Bun. The packages are not published to a registry. Build from the locked checkout to use the tested dependency artifacts; fresh tarball installs can resolve different SDK dependencies.

```sh
npm ci --ignore-scripts
npm run check

PI_NEARAI_POLICY=sdk PI_TINFOIL_POLICY=sdk \
  node_modules/.bin/pi \
  -e packages/nearai/dist/extension.js \
  -e packages/tinfoil/dist/extension.js
```

Log in through Pi's native secret prompts:

```text
/login nearai
/login tinfoil
```

Pi stores credentials and handles `/logout`. Stored keys take precedence over `NEARAI_API_KEY` and `TINFOIL_API_KEY`. Browser OAuth is not implemented.

### Choose a route

Routes are selected at startup. The defaults are NEAR's gateway and Tinfoil's router. The direct routes are experimental and require `sdk` policy.

| Setting | Route and requirements |
| --- | --- |
| `PI_NEARAI_ROUTE=gateway` | Default. The sampled gateway is blocked by its `OutOfDate` CPU status; verification requires `UpToDate`. |
| `PI_NEARAI_ROUTE=direct` | Only `z-ai/glm-5.3-flash`. Requires fresh UpToDate CPU evidence, GPU evidence, one authenticated TLS connection, OHTTP encryption and verified response signatures. [Details](docs/direct-access.md#near-direct-route-and-evidence). |
| `PI_TINFOIL_ROUTE=router` | Default. Uses the SDK's router/backend release policy and automatic key-rotation resend. |
| `PI_TINFOIL_ROUTE=direct` | Only `gemma4-31b`. Pins an AMD worker, release artifact and launch measurement; lacks fresh v3, revocation and independent GPU appraisal. [Details](packages/tinfoil/README.md). |
| `PI_TINFOIL_ROUTE=direct-intel` | Only `gemma4-31b`. Enforces fresh local Intel/NVIDIA appraisal with frozen policy and helper hashes. Requires the tested macOS ARM64 setup, configured local helpers and a pinned Docker image. [Trust inventory and setup](docs/intel-candidate.md). |

Direct routes bind inference to the attested TLS key and reject reconnect/resend. Passing their checks does not enable Approved mode.

### Commands and policy

`PI_NEARAI_POLICY` and `PI_TINFOIL_POLICY` accept `approved` or `sdk`. Omitted values select `approved`; unknown values reject extension loading. Session commands change policy without persisting it:

```text
/nearai status
/nearai models
/nearai models refresh
/nearai policy sdk
/nearai policy approved

/tinfoil status
/tinfoil models
/tinfoil models refresh
/tinfoil policy sdk
/tinfoil policy approved
```

Changing policy aborts active requests and updates model availability. Status reports list trust assumptions and mark independent approval, a closed trust set and whole-session protection as unestablished. Provider footers apply only to the selected provider. Ordinary logs exclude prompts, credentials, completions and quote bodies.

## Model discovery

Both providers discover chat models advertising tool support through public `/v1/models` catalogs, mapping modalities, context/output limits, reasoning controls and prices. These are provider claims, not deployment approval. Missing prices are labeled; NEAR pricing tiers beyond base costs are not modeled.

NEAR defaults to **TEE-only discovery**. Matching per-model metadata must declare `providerType: "vllm"` and `attestationSupported: true`. Non-TEE models, failed lookups and unknown entries are hidden. Older snapshots without capability metadata are treated as unknown.

Set `PI_NEARAI_MODEL_VISIBILITY=all` or run `/nearai models all` to show labeled, inference-blocked entries. `/nearai models tee` restores the filter; session choices are not persisted. Showing an entry does not authorize inference: unsupported and unknown models fail before SDK setup. Declared capability still requires verification. Approved mode hides all picker models regardless of this setting.

Online startup fetches the catalog. Pi stores snapshots and uses four-hour freshness checks for refreshes; failed refresh preserves cached models. Set `PI_TEE_OFFLINE=1` to skip startup discovery and restore the stored catalog. Use the commands above to force refresh: `pi update --models` does not load extensions. [Discovery implementation](packages/nearai/src/discovery.ts).

## Request behavior and security scope

The extensions use Pi's message conversion, tools, reasoning, usage accounting and cancellation. A guard checks the final serialized request after payload hooks, fixes the model/endpoint/auth headers and rejects caller transport overrides, unsupported fields, hosted tools and remote media URLs. Function tools and supported inline images are accepted.

Pi provider retries are disabled. Security and ambiguous-execution errors use terminal codes that also suppress Pi 1.0.4's turn and summarization retries; this must be rechecked on a Pi upgrade. Tinfoil's router retains its SDK rotation resend; direct routes send once.

NEAR holds response bytes in memory until the model signature is verified, delaying visible text and tool calls until completion. Plaintext bodies are capped at 8 MiB and encrypted network bodies at 32 MiB before decoding. Requests are capped at 16 MiB, catalogs at 2 MiB and request duration at ten minutes or a shorter caller timeout. These are body limits, not a total memory budget; verification keeps additional copies. There is no plaintext disk spill. Tinfoil streams authenticated encrypted responses.

**Protection applies to these providers' requests, not the entire Pi conversation.** Other providers, model switches, fallback, compaction, extensions and tools can access or transmit plaintext. Local code remains trusted. Registering another extension under the same provider ID can replace its implementation.

Approved mode remains blocked pending independent software/build approval and complete hardware, key-custody and runtime qualification. NEAR also needs a serving-session binding beyond shared certificates and model signers. Whole-session protection requires a guard after Pi resolves the physical provider, including summaries and fallback. Public source and successful SDK checks do not satisfy these requirements. See the [security contract](SECURITY.md), [design](docs/design.md) and [Intel candidate inventory](docs/intel-candidate.md).

## Validation

```sh
npm run check             # build, types and provider/security tests
npm run smoke             # compiled extensions, Pi loader and synthetic native login
npm run smoke:packages    # isolated tarball installs, loader and login
npm run smoke:catalogs    # public metadata; no credentials or inference
npm run smoke:attestation # Tinfoil router SDK verification; no inference
```

On 2026-10-07, **39 automated tests**, compiled-loader checks and isolated-package checks passed. Tarball loading does not qualify newly resolved verifier dependencies. The full actual Pi suite covers login, stored-key precedence, completion/usage, Unicode tools and follow-up, reasoning and RPC cancellation.

| Actual Pi route | Result |
| --- | --- |
| NEAR direct GLM | Full suite passed. |
| Tinfoil direct AMD Gemma | Full suite and streaming cancellation passed. |
| Tinfoil direct Intel Gemma | Full suite and streaming cancellation passed with fresh CPU/GPU appraisal. |
| Tinfoil router | Completion, tools and reasoning passed across separate runs; a cancellation retry passed. Intermittent SDK key mismatches remain unresolved. |

The [live Pi harness](scripts/live-pi.ts) sends capped synthetic prompts and uses an isolated credential store and harmless Unicode echo tool. It accepts a provider and optional model ID, using a key from the environment or a private dotenv file:

```sh
PI_NEARAI_ROUTE=direct node --env-file=/path/to/private/nearai.env \
  --import tsx scripts/live-pi.ts nearai z-ai/glm-5.3-flash

PI_TINFOIL_ROUTE=direct node --env-file=/path/to/private/tinfoil.env \
  --import tsx scripts/live-pi.ts tinfoil gemma4-31b
```

These tests are opt-in and billable. `--cancel-only` aborts at a response-consumption barrier; `--cancel-stream` aborts after a live text delta without that barrier. Cancellation checks local abort and acknowledgement, not remote generation-stop timing. The harness removes its temporary credential store and never prints keys or provider payloads. A terminal failure stops subsequent checks.

Detailed evidence, hardware negatives and remaining gates are in the [implementation record](docs/implementation.md) and [direct-worker assessment](docs/direct-access.md). Catalog counts are point-in-time observations; catalog presence does not establish attestation or approval.

The locked NEAR dependency chain has a low-severity [elliptic signing advisory](https://github.com/advisories/GHSA-848j-6mx2-7j84) with no patched release at the recorded check. The inspected DCAP path uses native Node verification; no signing call was found. [Dependency assessment](docs/implementation.md#validation).

Written by Codex.
