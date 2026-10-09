# pi-tee

NEAR AI and Tinfoil providers for Pi, with native API-key login, live model discovery, tools, reasoning, usage accounting and encrypted inference.

**Work in progress; packages are unpublished.** The default `public-builds,egress=metadata` admits freshly verified Tinfoil public workers with current firmware and protected GPUs. NEAR and the Tinfoil router require a position that trusts both provider and host. Each request selects the strongest route meeting every policy threshold. [Security model](docs/security-model.md).

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

No further setup is needed on any Pi platform. The NVIDIA verifier ships in `pi-tee-core` and Tinfoil's CPU/release verifier in `pi-tinfoil`, both as hash-checked WebAssembly that runs under Node and Bun. [Portable verification](docs/portable-verification.md).

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

Set `PI_TEE_POLICY=<position>[,axis=value…]` for both extensions. The four positions are `public-builds`, `public-builds-trust-host`, `trust-provider`, and `trust-provider-and-host`. Names disclose permitted trust; optional values set code, host, GPU, handling, build and review thresholds. The shipped default adds `egress=metadata` because no route supplies sealed handling.

Examples:

```sh
PI_TEE_POLICY=public-builds,egress=metadata pi -e ./packages/tinfoil/dist/extension.js
PI_TEE_POLICY=trust-provider-and-host,host=current pi -e ./packages/nearai/dist/extension.js
```

Tinfoil's qualified direct route supplies A1/H1/G1/X2/B3/S3. Its Genoa workers need H2 admission: `public-builds-trust-host,egress=metadata,host=outdated-firmware,gpu=verified`. Intel `OutOfDate` Tinfoil workers remain unavailable under every policy because the pinned verifier rejects them. The router is A3/H3/G3/X3. NEAR is A3/G3/X3, with H1 or H2 based on each instance's verified CPU evidence and local floors; only GLM-5.3 Flash has a direct adapter. Routes qualify independently, then code, host, GPU and egress break ties in that order.

`/status`, `/nearai status` and `/tinfoil status` show actual levels, who you trust, gaps, observations and selection reasons. `/nearai policy <setting>` and `/tinfoil policy <setting>` use the same syntax, abort active requests, and do not persist changes. `verifier=local` is the default; opt-in `verifier=nras` applies the same G checks and adds NVIDIA service trust. NEAR GPU diagnostics remain local and never gate its G3 admission.

Removed `sdk` migrates to `trust-provider-and-host`; `approved` points to the not-yet-supported `public-builds,review=pinned`. Replace `PI_NEARAI_POLICY`, `PI_TINFOIL_POLICY`, `PI_NEARAI_ROUTE` and `PI_TINFOIL_ROUTE` with `PI_TEE_POLICY`; old variables now return migration errors. Explicit bare `public-builds` requests `egress=none` and currently admits no route. [Defaults, forced combinations, route policies and limits](docs/security-model.md).

## Model discovery

Both providers fetch chat/tool models from public catalogs, mapping prices, context limits, modalities and reasoning controls. Catalog entries are provider claims; each request still needs verification. `/nearai models` and `/tinfoil models` inspect discovery; append `refresh` to force a refresh. Pi stores snapshots and uses four-hour freshness checks. Failed refreshes retain cached models; `PI_TEE_OFFLINE=1` skips startup discovery.

NEAR defaults to **TEE-only discovery**: metadata must match the model and declare `providerType: "vllm"` and `attestationSupported: true`. Non-TEE, unknown and failed lookups are hidden. `/nearai models all` or `PI_NEARAI_MODEL_VISIBILITY=all` shows labeled entries whose inference remains blocked; `/nearai models tee` restores the filter. Session choices are not persisted.

NEAR has no route qualifying for a public-build position. Tinfoil public builds show only the profile's models that the live catalog also lists. Missing prices are labeled, and NEAR pricing tiers beyond base costs are not modeled.

## Security scope

Public-build positions trust the named public maintainers, workflows and build processes, plus Intel/AMD/NVIDIA and the local installation, including the hash-checked WebAssembly verifiers. Compatible vendor releases are verified automatically without maintained deployment pins. A malicious authorized release can be accepted before detection; public evidence permits later auditing, not guaranteed detection. Changes to authorities, workload repositories, supported schemas/GPU configurations, SEV-SNP firmware or local verifier artifacts can require a client update. [Exact trust set and serving contract](docs/tinfoil-public-profile.md).

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

[CI](.github/workflows/ci.yml) runs the first three, the Go helper's checks and the Bun-specific tests on every push to `main` and pull request; the [WebAssembly verifier workflow](.github/workflows/wasm-verifiers.yml) rebuilds the modules and runs their tests on six platforms.

The security-model tests cover all position defaults, forced/category combinations, route thresholds, tie-breaking, report gaps and dispatch expiry. Private boot/artifact fixtures run locally and are skipped in CI. [Current CI and live results, including availability failures](docs/implementation.md#security-model-validation).

The [live Pi harness](scripts/live-pi.ts) sends capped synthetic prompts using an isolated credential store:

```sh
PI_TEE_POLICY=public-builds,egress=metadata node --env-file=/path/to/private/tinfoil.env \
  --import tsx scripts/live-pi.ts tinfoil deepseek-v4-1-flash --public-builds

PI_TEE_POLICY=trust-provider-and-host,host=current node --env-file=/path/to/private/nearai.env \
  --import tsx scripts/live-pi.ts nearai z-ai/glm-5.3-flash
```

Live tests are opt-in and billable. Add `--cancel-stream` to test abort after a text delta; set `PI_TEE_LIVE_PI_BINARY` to an absolute Pi binary path to test a compiled Pi. Cancellation establishes local abort and acknowledgement, not remote generation-stop timing. The harness removes its temporary credential store and never prints keys or provider payloads.

The [validation record](docs/implementation.md#validation) covers the other routes, unresolved router key-mismatch errors and the recorded NEAR dependency advisory. Independent Opus 5.5 reviews of the public profile, local setup and enablement are linked in the [serving contract](docs/tinfoil-public-profile.md).

Written by Codex.
