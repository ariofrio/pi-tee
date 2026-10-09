# Quick start

Use Node 24 and the locked checkout. Verifiers ship as hash-checked WebAssembly; no Docker, compiler or separately installed verifier is needed. [Runtime qualification and limits](reference/support-limits.md). Fresh tarball installs can resolve different SDK dependencies and need separate qualification.

```sh
npm ci --ignore-scripts
npm run check
node_modules/.bin/pi -e packages/tinfoil/dist/extension.js
```

In Pi, use `/login tinfoil` and enter the key through its secret prompt. Select a discovered model, then send a request. Under the default policy, Tinfoil public workers must qualify freshly; unavailable or rejected workers produce a terminal error. `/tinfoil status` explains the actual checks, gaps and route selection.

The extensions can run together:

```sh
node_modules/.bin/pi \
  -e packages/nearai/dist/extension.js \
  -e packages/tinfoil/dist/extension.js \
  -e packages/chutes/dist/extension.js \
  -e packages/privatemode/dist/extension.js
```

Use `/login nearai`, `/login chutes` or `/login privatemode` for their separate credentials. Pi stores keys and handles `/logout`; stored keys take precedence over provider API-key environment variables. Browser OAuth is not implemented.

## Choose an admitting policy

Read the [provider guide](providers.md) before permitting weaker levels. Examples from the checkout:

```sh
PI_TEE_POLICY=public-builds,egress=metadata \
  node_modules/.bin/pi -e packages/tinfoil/dist/extension.js
PI_TEE_POLICY=trust-provider-and-host,host=current \
  node_modules/.bin/pi -e packages/nearai/dist/extension.js
PI_TEE_POLICY=trust-provider-and-host,host=current \
  node_modules/.bin/pi -e packages/chutes/dist/extension.js
PI_TEE_POLICY=trust-provider-and-host,code=fixed-private \
  node_modules/.bin/pi -e packages/privatemode/dist/extension.js
```

These are thresholds, not guaranteed availability. An outdated NEAR/Chutes instance fails `host=current`; Privatemode cannot establish fresh serving-worker CPUs. The [policy reference](reference/policy.md) explains all combinations and migration errors.

## Diagnose a blocked request

- Run `/<provider> status`: before verification, levels are not established; afterwards it lists actual levels, failing axes and sanitized observations.
- Run `/<provider> models refresh` to refresh discovery. Catalogs are provider claims, never security evidence. Failed refresh retains the previous snapshot.
- Check the [provider page](providers.md) for route-specific limits. A failed check does not relax policy, resend content or silently authorize a weaker route.
- Use `/<provider> policy <setting>` only when you intend to change that provider's trust. It aborts active requests and lasts for the session.

Tests and opt-in live qualification belong in [procedures](procedures/README.md); prior outcomes belong in [evidence](evidence/README.md).
