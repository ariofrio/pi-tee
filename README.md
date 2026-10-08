# pi-tee

NEAR AI and Tinfoil providers for Pi, with native API-key login, live model discovery, tools, reasoning, usage accounting and encrypted inference.

**Work in progress; packages are unpublished.** The default `public-builds` policy currently admits no models: Tinfoil Gemma 4 31B, DeepSeek V4.1 Flash and GLM-5.3 await independent review of the new verifiers. The same appraisal already serves them on the experimental `sdk`-policy `direct-public` route. Tinfoil's other models are reachable only through a router that does not enforce the policy. [Coverage](docs/design.md#provider-assessment). NEAR's `sdk` routes work, but NEAR public builds are not possible today: NEAR's operator deploys serving software at runtime without a public release process, so no client can confine its keys. [Why](docs/nearai-status.md).

| Package | Purpose |
| --- | --- |
| [pi-nearai](packages/nearai/README.md) | NEAR provider with encryption and response-signature verification. |
| [pi-tinfoil](packages/tinfoil/README.md) | Tinfoil provider with attestation and encrypted HTTP bodies. |
| [pi-tee-core](packages/core/README.md) | Shared policy, discovery and transport guards; not a Pi extension. |

The extensions can run together with separate credentials. Each loads only its own provider SDK.

## Build and run

Use Node 24 and the locked checkout, which includes Pi 1.0.4. Fresh tarball installs may resolve different SDK dependencies.

```sh
npm ci --ignore-scripts
npm run check
```

No further setup is needed on any Pi platform. The CPU/release and NVIDIA verifiers ship in `pi-tinfoil` as hash-checked WebAssembly and run under Node and Bun. [Portable verification](docs/portable-verification.md).

```sh
node_modules/.bin/pi \
  -e packages/nearai/dist/extension.js \
  -e packages/tinfoil/dist/extension.js
```

Log in through Pi's secret prompts:

```text
/login nearai
/login tinfoil
```

Pi stores credentials and handles `/logout`. Stored keys take precedence over `NEARAI_API_KEY` and `TINFOIL_API_KEY`. Browser OAuth is not implemented.

## Policy and routes

`PI_NEARAI_POLICY` and `PI_TINFOIL_POLICY` select policy at startup:

| Policy | Behavior |
| --- | --- |
| `public-builds` | Default. Currently admits no models; Tinfoil Gemma 4 31B, DeepSeek V4.1 Flash and GLM-5.3 await review. NEAR cannot qualify. |
| `sdk` | Enables experimental routes under their disclosed trust assumptions. |
| `approved` | Reserved for independently approved frozen workloads; no profile is implemented. |

Use `/nearai policy sdk`, `/tinfoil policy sdk` or the corresponding `policy public-builds` command to switch during a session. Changes abort active requests and are not persisted. Verification failures never fall back to SDK policy.

Routes are selected at startup:

| Setting | Route |
| --- | --- |
| `PI_TINFOIL_ROUTE=auto` | Default. Public policy is paused; SDK policy uses the router catalog. |
| `PI_TINFOIL_ROUTE=direct-public` | Same public profile, explicitly selected. Under `sdk` policy it runs the full public-build appraisal while production admission awaits review. |
| `PI_TINFOIL_ROUTE=router` | SDK policy only. Trusts the router's backend release policy and permits its SDK key-rotation resend. |
| `PI_TINFOIL_ROUTE=direct` | SDK policy only. Frozen AMD Gemma worker; lacks fresh v3, revocation and independent GPU appraisal. |
| `PI_NEARAI_ROUTE=gateway` | Default NEAR SDK route. Both observed gateway instances failed the required `UpToDate` CPU check on 2026-10-07; [evidence](docs/near-gateway-evidence.json). |
| `PI_NEARAI_ROUTE=direct` | SDK policy only. Restricts discovery to `z-ai/glm-5.3-flash` and binds inference to one attested TLS connection. |

See the [Tinfoil route details](packages/tinfoil/README.md) and [NEAR direct assessment](docs/direct-access.md#near-direct-route-and-evidence) for requirements and limitations.

`/nearai status` and `/tinfoil status` show policy and trust assumptions. A successful public dispatch reports `publicBuildVerification: profile-established`, `closedTrustSet: profile-declared`, artifact digests and appraisal expiry. Independent approval and whole-session protection remain `not-established`.

## Model discovery

Both providers fetch chat/tool models from public catalogs, mapping prices, context limits, modalities and reasoning controls. Catalog entries are provider claims; each request still needs verification. `/nearai models` and `/tinfoil models` inspect discovery; append `refresh` to force a refresh. Pi stores snapshots and uses four-hour freshness checks. Failed refreshes retain cached models; `PI_TEE_OFFLINE=1` skips startup discovery.

NEAR defaults to **TEE-only discovery**: metadata must match the model and declare `providerType: "vllm"` and `attestationSupported: true`. Non-TEE, unknown and failed lookups are hidden. `/nearai models all` or `PI_NEARAI_MODEL_VISIBILITY=all` shows labeled entries whose inference remains blocked; `/nearai models tee` restores the filter. Session choices are not persisted.

NEAR public-build and Approved policies show no selectable models. Tinfoil public builds show no models until review. Missing prices are labeled, and NEAR pricing tiers beyond base costs are not modeled.

## Security scope

Public-build policy trusts the named public maintainers, workflows and build processes, plus Intel/AMD/NVIDIA and the local installation, including the hash-checked WebAssembly verifiers. Compatible vendor releases are verified automatically without maintained deployment pins. A malicious authorized release can be accepted before detection; public evidence permits later auditing, not guaranteed detection. Changes to authorities, workload repositories, supported schemas/GPU configurations, SEV-SNP firmware or local verifier artifacts can require a client update. [Exact trust set and serving contract](docs/tinfoil-public-profile.md).

The final request guard fixes model, endpoint and authentication after Pi's payload hooks, rejecting transport overrides, hosted tools, remote media and unsupported fields. Direct routes bind the actual TLS socket before credentials or ciphertext, send once and reject reconnect/resend. Pi provider retries are disabled; terminal security errors also suppress Pi 1.0.4's turn/summarization retries. The SDK router retains its disclosed rotation resend.

NEAR buffers bounded response bytes in memory until signature verification; Tinfoil streams authenticated encrypted responses. Ordinary logs exclude credentials, prompts, completions and quote bodies. [Security guarantees and limits](SECURITY.md).

**These extensions protect their own requests, not the entire Pi conversation.** Other providers, fallback, compaction, extensions and tools can access or transmit plaintext. Local code remains trusted. The [NEAR assessment](docs/nearai-status.md) explains why NEAR public builds need NEAR server changes.

## Validation

```sh
npm run check             # build, types and provider/security tests
npm run smoke             # compiled loading and native login
npm run smoke:packages    # isolated tarball loading and login
npm run smoke:catalogs    # public metadata; no inference
npm run smoke:attestation # router SDK attestation; no inference
npm run check:nvidia      # WebAssembly NVIDIA verifier negatives; no inference
npm run build:wasm        # maintainers: rebuild the WebAssembly verifiers
```

On 2026-10-08, `npm run check` passed 77 tests; three more need private evidence fixtures or boot artifacts and also passed. The experimental `direct-public` route, which runs the full public-build appraisal through the WebAssembly verifiers, passed the actual Pi suite for all three models under Node and the Bun-compiled Pi 1.0.4 binary: login, stored-key precedence, completion/usage, Unicode tools and follow-up, reasoning, and cancellation, including after a live text delta. [Portable verification evidence](docs/portable-verification.md#evidence).

The [live Pi harness](scripts/live-pi.ts) sends capped synthetic prompts using an isolated credential store:

```sh
PI_TINFOIL_POLICY=sdk PI_TINFOIL_ROUTE=direct-public node --env-file=/path/to/private/tinfoil.env \
  --import tsx scripts/live-pi.ts tinfoil gemma4-31b

PI_NEARAI_ROUTE=direct node --env-file=/path/to/private/nearai.env \
  --import tsx scripts/live-pi.ts nearai z-ai/glm-5.3-flash
```

Live tests are opt-in and billable. Add `--cancel-stream` to test abort after a text delta; set `PI_TEE_LIVE_PI_BINARY` to an absolute Pi binary path to test a compiled Pi. Cancellation establishes local abort and acknowledgement, not remote generation-stop timing. The harness removes its temporary credential store and never prints keys or provider payloads.

The [validation record](docs/implementation.md#validation) covers the other routes, unresolved router key-mismatch errors and the recorded NEAR dependency advisory. Independent Opus 5.5 reviews of the public profile, local setup and enablement are linked in the [serving contract](docs/tinfoil-public-profile.md).

Written by Codex.
