# pi-tee

NEAR AI and Tinfoil providers for Pi, with native API-key login, live model discovery, tools, reasoning, usage accounting and encrypted inference.

**Work in progress; packages are unpublished.** The default `public-builds` policy supports Tinfoil `gemma4-31b` on the tested macOS ARM64/OrbStack setup. NEAR's experimental direct `sdk` route works; its public-build profile needs more client implementation, deployment evidence and backend bindings. [What is missing for NEAR](docs/nearai-status.md).

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

For Tinfoil public builds, install the local verifiers. The tested setup requires **macOS ARM64, Go, OrbStack, Docker 29.4.0, buildx 0.33.0 and the containerd image store**. Setup selects Go 1.26.6 and checks the built helper and image hashes. Docker Desktop sockets are recognized, but its setup is unvalidated; incompatible builders fail closed. [Setup and artifact inventory](docs/intel-candidate.md#local-setup).

```sh
node packages/tinfoil/dist/setup.js --directory "$PWD/local-verifiers"
export PI_TINFOIL_PUBLIC_BUILD_VERIFIER="$PWD/local-verifiers/tinfoil-public-build-verifier"
export PI_TINFOIL_NVAT_DIR="$PWD/local-verifiers/libnvat-linux-sbsa-1.2.2.1780962352-archive"

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
| `public-builds` | Default. Tinfoil admits the supported Gemma profile after fresh verification. NEAR is blocked. |
| `sdk` | Enables experimental routes under their disclosed trust assumptions. |
| `approved` | Reserved for independently approved frozen workloads; no profile is implemented. |

Use `/nearai policy sdk`, `/tinfoil policy sdk` or the corresponding `policy public-builds` command to switch during a session. Changes abort active requests and are not persisted. Verification failures never fall back to SDK policy.

Routes are selected at startup:

| Setting | Route |
| --- | --- |
| `PI_TINFOIL_ROUTE=auto` | Default. Public policy uses the verified Intel Gemma worker; SDK policy uses the router catalog. |
| `PI_TINFOIL_ROUTE=direct-public` | Same public profile, explicitly selected. |
| `PI_TINFOIL_ROUTE=router` | SDK policy only. Trusts the router's backend release policy and permits its SDK key-rotation resend. |
| `PI_TINFOIL_ROUTE=direct` | SDK policy only. Frozen AMD Gemma worker; lacks fresh v3, revocation and independent GPU appraisal. |
| `PI_TINFOIL_ROUTE=direct-intel` | SDK policy only. Frozen Intel/GPU research profile with separate helper configuration. |
| `PI_NEARAI_ROUTE=gateway` | Default NEAR SDK route. Both observed gateway instances failed the required `UpToDate` CPU check on 2026-10-07; [fleet-wide status is unknown](docs/nearai-status.md#how-many-gateways-are-affected). |
| `PI_NEARAI_ROUTE=direct` | SDK policy only. Restricts discovery to `z-ai/glm-5.3-flash` and binds inference to one attested TLS connection. |

See the [Tinfoil route details](packages/tinfoil/README.md) and [NEAR direct assessment](docs/direct-access.md#near-direct-route-and-evidence) for requirements and limitations.

`/nearai status` and `/tinfoil status` show policy and trust assumptions. A successful public dispatch reports `publicBuildVerification: profile-established`, `closedTrustSet: profile-declared`, artifact digests and appraisal expiry. Independent approval and whole-session protection remain `not-established`.

## Model discovery

Both providers fetch chat/tool models from public catalogs, mapping prices, context limits, modalities and reasoning controls. Catalog entries are provider claims; each request still needs verification. `/nearai models` and `/tinfoil models` inspect discovery; append `refresh` to force a refresh. Pi stores snapshots and uses four-hour freshness checks. Failed refreshes retain cached models; `PI_TEE_OFFLINE=1` skips startup discovery.

NEAR defaults to **TEE-only discovery**: metadata must match the model and declare `providerType: "vllm"` and `attestationSupported: true`. Non-TEE, unknown and failed lookups are hidden. `/nearai models all` or `PI_NEARAI_MODEL_VISIBILITY=all` shows labeled entries whose inference remains blocked; `/nearai models tee` restores the filter. Session choices are not persisted.

NEAR public-build and Approved policies show no selectable models. Tinfoil public builds show only Gemma; unsupported runtimes, missing helpers and failed appraisal reject before inference. Missing prices are labeled, and NEAR pricing tiers beyond base costs are not modeled.

## Security scope

Public-build policy trusts the named public maintainers, workflows and build processes, plus Intel/NVIDIA and the local installation. Compatible vendor releases are verified automatically without maintained deployment pins. A malicious authorized release can be accepted before detection; public evidence permits later auditing, not guaranteed detection. Changes to authorities, supported schemas/GPU families or local verifier artifacts can require a client update. [Exact trust set and serving contract](docs/tinfoil-public-profile.md).

The final request guard fixes model, endpoint and authentication after Pi's payload hooks, rejecting transport overrides, hosted tools, remote media and unsupported fields. Direct routes bind the actual TLS socket before credentials or ciphertext, send once and reject reconnect/resend. Pi provider retries are disabled; terminal security errors also suppress Pi 1.0.4's turn/summarization retries. The SDK router retains its disclosed rotation resend.

NEAR buffers bounded response bytes in memory until signature verification; Tinfoil streams authenticated encrypted responses. Ordinary logs exclude credentials, prompts, completions and quote bodies. [Security guarantees and limits](SECURITY.md).

**These extensions protect their own requests, not the entire Pi conversation.** Other providers, fallback, compaction, extensions and tools can access or transmit plaintext. Local code remains trusted. The [NEAR assessment](docs/nearai-status.md) explains which remaining guarantees need client work, deployment investigation or server support.

## Validation

```sh
npm run check             # build, types and provider/security tests
npm run smoke             # compiled loading and native login
npm run smoke:packages    # isolated tarball loading and login
npm run smoke:catalogs    # public metadata; no inference
npm run smoke:attestation # router SDK attestation; no inference
```

On 2026-10-07, the qualification run passed **62/62 tests using private evidence fixtures**, plus compiled-loader and isolated-package checks. Without those fixtures, three tests skip. The production Tinfoil public-policy Pi suite passed login, stored-key precedence, completion/usage, Unicode tools and follow-up, reasoning and cancellation, including a separate abort after a live text delta. [Recorded results](docs/public-profile-validation.json).

The [live Pi harness](scripts/live-pi.ts) sends capped synthetic prompts using an isolated credential store:

```sh
# With the local verifiers configured above:
node --env-file=/path/to/private/tinfoil.env \
  --import tsx scripts/live-pi.ts tinfoil gemma4-31b --public-builds

PI_NEARAI_ROUTE=direct node --env-file=/path/to/private/nearai.env \
  --import tsx scripts/live-pi.ts nearai z-ai/glm-5.3-flash
```

Live tests are opt-in and billable. Add `--cancel-stream` to test abort after a text delta. Cancellation establishes local abort and acknowledgement, not remote generation-stop timing. The harness removes its temporary credential store and never prints keys or provider payloads.

The [validation record](docs/implementation.md#validation) covers the other routes, unresolved router key-mismatch errors and the recorded NEAR dependency advisory. Independent Opus 5.5 reviews of the public profile, local setup and enablement are linked in the [serving contract](docs/tinfoil-public-profile.md).

Written by Codex.
