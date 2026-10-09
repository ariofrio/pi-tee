# pi-privatemode

Privatemode extension for Pi 1.0.4 with native API-key login, model discovery, streamed chat, tools, reasoning, usage and cancellation. Packages are unpublished; use the locked Node 24 [checkout/quick start](https://github.com/ariofrio/pi-tee/blob/main/docs/quick-start.md). Each extension loads its own provider dependencies and shared `pi-tee-core`.

From the checkout:

```sh
npm ci --ignore-scripts
npm run check
PI_TEE_POLICY=trust-provider-and-host,code=fixed-private \
  node_modules/.bin/pi -e packages/privatemode/dist/extension.js
```

Use `/login privatemode`; Pi's stored key wins over `PRIVATEMODE_API_KEY`. `/logout` removes it. `/privatemode status`, `/privatemode models refresh` and `/privatemode policy <setting>` use the [shared command contract](https://github.com/ariofrio/pi-tee/blob/main/docs/reference/commands-settings.md). Policy changes abort active requests and are session-only.

A2/H3/G3/X3. Exact manifest pins and fresh Coordinator/mesh key checks do not establish fresh workers, complete GPUs or metadata-only handling. Read the [provider guide](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/privatemode.md) for admitting policies, exact credentials/plaintext recipients and diagnosis; [policy](https://github.com/ariofrio/pi-tee/blob/main/docs/reference/policy.md) defines syntax/migration. Catalogs and earlier runs never authorize a new request.

These protections cover this provider's dispatches. Local code and other Pi providers/tools can transmit conversation plaintext. [Security boundary](https://github.com/ariofrio/pi-tee/blob/main/SECURITY.md), [runtime/response limits](https://github.com/ariofrio/pi-tee/blob/main/docs/reference/support-limits.md), [qualification evidence](https://github.com/ariofrio/pi-tee/blob/main/docs/evidence/README.md).

Library API: `createPrivatemodeProvider()` from `pi-privatemode`; `dist/extension.js` is the Pi entry point. Manifest API: `ManifestAdmissionPolicy.admit(signal)`, `createPinnedManifestPolicy()`, `createRecordedCdnManifestPolicy()` and `manifestRecorder()` are exported. Returned bytes are rehashed/recorded before bootstrap; a custom policy cannot raise A2 without a separate verified release/closure implementation. [Source](https://github.com/ariofrio/pi-tee/blob/main/packages/privatemode/src/manifest.ts).

Fresh tarballs may resolve different SDK dependencies and require separate qualification.

Written by Codex.

## Earlier section links

<a id="setup-and-policy"></a>

See [Setup and policy](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/privatemode.md).

<a id="manifest-admission"></a>

See [Manifest admission](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/privatemode.md).

<a id="plaintext-and-metadata"></a>

See [Plaintext and metadata](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/privatemode.md).

<a id="models-and-validation"></a>

See [Models and validation](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/privatemode.md).

<a id="authenticated-attestationkey-negatives-zero-inference"></a>

See [Authenticated attestation/key negatives, zero inference:](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/privatemode.md).

<a id="capped-synthetic-completion-tools-reasoning-and-cancellation"></a>

See [Capped synthetic completion, tools, reasoning and cancellation:](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/privatemode.md).

<a id="bun-reads-typescript-directly-use-bun---env-file-scriptslive-pits-"></a>

See [Bun reads TypeScript directly; use bun --env-file=... scripts/live-pi.ts ...](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/privatemode.md).
