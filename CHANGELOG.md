# Changelog

## Unreleased

### Added

- Four separate Pi extensions: NEAR AI, Tinfoil, Chutes and Privatemode, with native API-key login, discovery, tools, reasoning, usage and cancellation. Packages remain unpublished. [Provider guide](docs/providers.md).
- Tinfoil public direct workers for Gemma 4 31B, DeepSeek V4.1 Flash and GLM-5.3, plus a DeepSeek/GLM billing-relay fallback. Fresh public release/runtime/key, CPU and serving-GPU checks precede inference; direct is preferred. [Serving contract](docs/contracts/tinfoil-public-builds.md).
- Hash-checked local WASM verifiers, isolated workers, owned TLS transport and six desktop Node/Bun host checks; no user-installed compiler/container. Android emulator results have a narrower credential-free scope. [Support](docs/reference/support-limits.md), [evidence](docs/evidence/README.md).

### Changed

- `PI_TEE_POLICY` uses four named trust positions and explicit thresholds. The default is `public-builds,egress=metadata`; route admission checks every axis and compares code, host, GPU and handling. Build reproduction/pinned review remain unsupported. [Policy and migration](docs/reference/policy.md).
- NEAR direct discovers matching tool-chat catalog/registry endpoints. NEAR/Chutes establish fresh H1/H2 locally while remaining A3/G3/X3; optional NEAR GPU diagnostics never gate admission or contact NRAS, and GPU evidence that reaches the SDK is rejected locally instead of using its NRAS default. Privatemode remains A2/H3/G3/X3 under exact hard-pin or explicit logged-CDN manifest admission.
- Tinfoil platform authority is the exact `cvmimage` platform-release workflow; strict v2 references require an authenticated same-release classic companion. Genoa H2 retains publisher minima/production checks; Intel OutOfDate public workers remain unavailable. NRAS authenticates device/overall tokens under the same GPU gates.
- NEAR's gateway route keeps NEAR's SDK protocol but owns its connection: gateway evidence, model evidence, the sealed request and its signature share one TLS socket to the quote-bound key, instead of a new SDK connection per request. The route now runs under Bun. [NEAR routes](docs/providers/nearai.md#routes-and-admission).
- Chutes encryption is checked in CI against Chutes' own browser test client, fetched by commit and hash: the two clients' requests are equivalent and their streamed responses interoperate. The runtime keeps its Noble implementation. [Chutes content](docs/providers/chutes.md#content-and-metadata).
- The Tinfoil router no longer uses Tinfoil's SDK. pi-tee appraises it under a fresh nonce with revocation, firmware floors and its public release workflow, then sends once over its attested keys. It remains A3/H3/G3/X3. [Router](docs/providers/tinfoil.md#router).
- User guides, policy/hardware reference and maintainer procedures now have separate homes. Dated investigations/reviews keep their scopes, verdicts and compatibility links; verifier rationale lives beside code. The comment-only Go update includes a rebuilt CI artifact/pin, without changing verifier logic.

### Fixed

- Preserve native credential selection across all four extensions; reject ambiguous Privatemode attestation-field aliases and manifest/policy mismatches before inference.
- Guard final post-hook payload/model/endpoint/authentication; bind actual sockets/recipient keys, bound memory/time and reject forged output, reconnects and unwanted resends. Chutes' owned invocation socket cannot replay HTTP 421.
- Status names why a host failed with its HTTP status and a fixed class (rate-limited, upstream unavailable, evidence unavailable, request refused, connection failed), never provider text. Terminal codes thrown during dispatch, such as a rejected Tinfoil wire status, now surface instead of `TEE_REQUEST_FAILED`. [Diagnosis](docs/quick-start.md#diagnose-a-blocked-request).
- Pi's thinking level now takes effect on NEAR, Chutes and Tinfoil reasoning models whose hosts ignored it. Qwen3.8, GLM-5.2, GLM-5.3 and Kimi-K3 receive their own effort names, so "high" selects each model's own high; other reasoning models switch thinking off at "off", which several otherwise enable by default, and on at any other level. Effort values that some models refuse are no longer sent. [Thinking levels](docs/providers.md).
- Correct documentation facts/links and reconcile anonymous versus credentialed provider evidence. Document Privatemode runtime-added gateway headers and the cost of Tinfoil per-request cache salts. Local Markdown links are checked in CI.

### Security and limits

- These extensions protect their own dispatches; whole-session protection and independent approval remain unestablished. Local code, named public publishers/manufacturers, and weaker routes' explicitly admitted provider/host trust remain required. [Security boundary](SECURITY.md).
- Gateways can receive credentials/routing metadata while bodies stay encrypted. Tinfoil relay frame-boundary truncation and same-worker request replay can affect completeness/billing. Fresh per-request cache salts defeat cross-turn prompt caching and can increase prefill cost. [Exact disclosures](docs/providers.md).
- Validation is scoped to its commit, lock, route, runtime and sampled population. Private/raw evidence and live inference are separate from ordinary CI. [Evidence index](docs/evidence/README.md).

### Removed

- `sdk`/`approved` policy names and provider-specific policy/route environment variables: migration errors replace aliases. Old native/Docker setup commands and the retired platform authority are not current options.
- The unreachable hand-pinned Gemma Tinfoil worker transport and its profile. The `direct` route option already selects the public-build direct route.

## Earlier development history

The complete [pre-release development chronology](docs/archive/changelog/pre-release-development.md) is preserved, including failures and superseded implementations. No release dates or versions have been invented. On release, freeze its section and start a fresh Unreleased; move older released sections verbatim to version/year archives with a linked index when length warrants it.

Written by Codex.
