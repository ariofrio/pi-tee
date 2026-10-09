# pi-tee-core

Shared enforcement library for Pi provider extensions; not an extension and imports no provider SDK. Tested with Pi 1.0.4 and the locked dependency set. User-facing [security model](https://github.com/ariofrio/pi-tee/blob/main/docs/security-model.md) and [policy reference](https://github.com/ariofrio/pi-tee/blob/main/docs/reference/policy.md) define semantics.

| API group | Symbols / adapter responsibility |
| --- | --- |
| Policy and admission | `parsePolicy`, `assessRoute`, `weakestRoute`, `compareRoutes`: record only established levels; count all plaintext/key recipients |
| Native provider | `createTeeProvider`, `TeeRouteDefinition`, `SdkTransport`: content-free candidate appraisal, owned transport/disposal, catalog publication and status; `fallbackFor` skips an unnecessary fallback when its preferred route qualifies |
| Payload/output | `guardChatFetch`, `authenticateResponse`: guard final converted payload after hooks; authenticate bounded output before exposing text/tools |
| Owned TLS | `pinnedTlsFetch`, `webPkiTlsFetch`: actual-socket binding versus disclosed WebPKI metadata recipient, TLS 1.3 and one request |
| Hardware rating | `rateAuthenticatedTdxHost`, `tdxMeetsFloors`, `snpMeetsFloors`: call only after manufacturer authentication; these helpers do not authenticate evidence or establish freshness |
| GPU verification | `runNvidiaVerifier`, `runNrasVerifier`, `checkGpuAppraisal`, `rateGpuAppraisal`: same mode/coverage/floor rules; remote verdict alone cannot establish admission |
| WASI/reporting | `runWasiCommand`, `formatProviderReport`: bounded isolated verifier execution; content-free trust/gap/selection reports |

Potential levels and catalog flags only filter discovery. Native dispatch rechecks policy epoch/expiry; losing sessions are disposed. Non-public routes require explicit ratings; legacy public-profile registration remains for local integrations. Custom adapters are trusted local code. [Interface rationale and source links](https://github.com/ariofrio/pi-tee/blob/main/docs/design/architecture.md), [runtime limits](https://github.com/ariofrio/pi-tee/blob/main/docs/reference/support-limits.md).

The package ships hash-checked NVIDIA WASM and [third-party notices](wasm/THIRD_PARTY_LICENSES.txt). [Build/reproducibility procedure](https://github.com/ariofrio/pi-tee/blob/main/docs/procedures/verifier-builds.md). Protecting a dispatch does not establish whole-session protection or independent approval.
