# pi-tee

NEAR AI, Tinfoil, Chutes and Privatemode extensions for Pi: native API-key login, model discovery, tools, reasoning, usage and encrypted inference. **Work in progress; packages are unpublished.** Use the locked Node 24 checkout with Pi 1.0.4.

Start with the [quick start](docs/quick-start.md). The default `public-builds,egress=metadata` admits Tinfoil workers only after fresh public-build, CPU and GPU checks pass. Other routes require explicit provider and host trust. Every request establishes its own levels; a catalog label or previous success cannot authorize it.

| Read next | Purpose |
| --- | --- |
| [Security model](docs/security-model.md) | What verified levels mean and who remains trusted |
| [Provider guide](docs/providers.md) | Supported routes, admitting policies and provider limitations |
| [Reference](docs/reference/README.md) | Policy syntax, commands, settings, support limits and hardware floors |
| [Security boundary](SECURITY.md) | What the extensions protect and contributor obligations |
| [Contributing](CONTRIBUTING.md) | Required checks and review; [procedures](docs/procedures/README.md) and [dated evidence](docs/evidence/README.md) are separate |

## Credential and gateway disclosure

Bodies are encrypted, but credentials and routing metadata have their own recipients. These disclosures supplement route levels; they do not improve them.

| Route | Credential and metadata recipient |
| --- | --- |
| NEAR direct / Tinfoil direct | Credentials reach the freshly appraised TLS endpoint; its SPKI is checked on the actual socket before transmission. |
| NEAR gateway / Tinfoil router | The authenticated gateway/router and their disclosed plaintext/key recipients remain trusted. See [NEAR](docs/providers/nearai.md) and [Tinfoil](docs/providers/tinfoil.md). |
| Tinfoil billing gateway | Unattested WebPKI gateway sees API key, model, headers and worker host; body stays sealed to the appraised worker. Direct is preferred. [Replay and completeness limits](docs/providers/tinfoil.md#billing-gateway). |
| Chutes API | WebPKI API sees API key, chute/instance IDs, invocation token, fixed routing headers and traffic metadata. Complete chat content stays encrypted to the freshly verified instance key. [Exact fields](docs/providers/chutes.md#content-and-metadata). |
| Privatemode gateway | WebPKI gateway sees bearer key, path/model, client/version, request/secret IDs, salted shard keys, token estimates, OAE public headers, **runtime-added User-Agent/accept-* headers**, ciphertext sizes, IP and timing. [Exact recipients](docs/providers/privatemode.md#plaintext-and-metadata). |

Tinfoil public requests use a fresh encrypted `cache_salt` per dispatch. This defeats cross-turn prompt caching and can increase prefill work and cost. [Provider limits](docs/providers/tinfoil.md#limits-and-diagnosis).

**The extensions protect their own requests.** Other Pi providers, fallback, compaction, extensions and tools can access or transmit conversation plaintext. Your OS, runtime and enabled local code remain trusted. Public-build policies also trust named publishers and build workflows: compatible releases update automatically, and a malicious authorized release may be accepted before detection. [Serving contract](docs/contracts/tinfoil-public-builds.md).

Provider packages: [pi-nearai](packages/nearai/README.md), [pi-tinfoil](packages/tinfoil/README.md), [pi-chutes](packages/chutes/README.md), [pi-privatemode](packages/privatemode/README.md). [pi-tee-core](packages/core/README.md) is the shared library, not an extension. Each extension loads only its own provider dependencies.

Written by Codex.
