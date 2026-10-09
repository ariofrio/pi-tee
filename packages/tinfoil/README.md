# pi-tinfoil

Tinfoil extension for Pi 1.0.4 with native API-key login, model discovery, streamed chat, tools, reasoning, usage and cancellation. Packages are unpublished; use the locked Node 24 [checkout/quick start](https://github.com/ariofrio/pi-tee/blob/main/docs/quick-start.md). Each extension loads its own provider dependencies and shared `pi-tee-core`.

From the checkout:

```sh
npm ci --ignore-scripts
npm run check
PI_TEE_POLICY=public-builds,egress=metadata \
  node_modules/.bin/pi -e packages/tinfoil/dist/extension.js
```

Use `/login tinfoil`; Pi's stored key wins over `TINFOIL_API_KEY`. `/logout` removes it. `/tinfoil status`, `/tinfoil models refresh` and `/tinfoil policy <setting>` use the [shared command contract](https://github.com/ariofrio/pi-tee/blob/main/docs/reference/commands-settings.md). Policy changes abort active requests and are session-only.

Public direct/gateway can be A1/H1/G1/X2/B3/S3 after checks; the router is A3/H3/G3/X3 and needs explicit trust. Gateway replay/truncation remain disclosed. Read the [provider guide](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/tinfoil.md) for admitting policies, exact credentials/plaintext recipients and diagnosis; [policy](https://github.com/ariofrio/pi-tee/blob/main/docs/reference/policy.md) defines syntax/migration. Catalogs and earlier runs never authorize a new request.

These protections cover this provider's dispatches. Local code and other Pi providers/tools can transmit conversation plaintext. [Security boundary](https://github.com/ariofrio/pi-tee/blob/main/SECURITY.md), [runtime/response limits](https://github.com/ariofrio/pi-tee/blob/main/docs/reference/support-limits.md), [qualification evidence](https://github.com/ariofrio/pi-tee/blob/main/docs/evidence/README.md).

Library API: `createTinfoilProvider()` from `pi-tinfoil`; `dist/extension.js` is the Pi entry point. Fresh tarballs may resolve different SDK dependencies and require separate qualification.

Written by Codex.

## Earlier section links

<a id="policy-and-direct-workers"></a>

See [Policy and direct workers](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/tinfoil.md).

<a id="billing-gateway"></a>

See [Billing gateway](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/tinfoil.md).

<a id="router-and-reporting"></a>

See [Router and reporting](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/tinfoil.md).
