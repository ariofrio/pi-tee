# pi-nearai

NEAR AI extension for Pi 1.0.4 with native API-key login, model discovery, streamed chat, tools, reasoning, usage and cancellation. Packages are unpublished; use the locked Node 24 [checkout/quick start](https://github.com/ariofrio/pi-tee/blob/main/docs/quick-start.md). Each extension loads its own provider dependencies and shared `pi-tee-core`.

From the checkout:

```sh
npm ci --ignore-scripts
npm run check
PI_TEE_POLICY=trust-provider-and-host,host=current \
  node_modules/.bin/pi -e packages/nearai/dist/extension.js
```

Use `/login nearai`; Pi's stored key wins over `NEARAI_API_KEY`. `/logout` removes it. `/nearai status`, `/nearai models refresh` and `/nearai policy <setting>` use the [shared command contract](https://github.com/ariofrio/pi-tee/blob/main/docs/reference/commands-settings.md). Policy changes abort active requests and are session-only.

A3/G3/X3; H1/H2 per request. Direct supports Node/Bun; SDK gateway is Node-only. Read the [provider guide](https://github.com/ariofrio/pi-tee/blob/main/docs/providers/nearai.md) for admitting policies, exact credentials/plaintext recipients and diagnosis; [policy](https://github.com/ariofrio/pi-tee/blob/main/docs/reference/policy.md) defines syntax/migration. Catalogs and earlier runs never authorize a new request.

These protections cover this provider's dispatches. Local code and other Pi providers/tools can transmit conversation plaintext. [Security boundary](https://github.com/ariofrio/pi-tee/blob/main/SECURITY.md), [runtime/response limits](https://github.com/ariofrio/pi-tee/blob/main/docs/reference/support-limits.md), [qualification evidence](https://github.com/ariofrio/pi-tee/blob/main/docs/evidence/README.md).

Library API: `createNearProvider()` from `pi-nearai`; `dist/extension.js` is the Pi entry point. Fresh tarballs may resolve different SDK dependencies and require separate qualification.

Written by Codex.
