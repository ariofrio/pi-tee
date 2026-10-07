# pi-tee-core

Shared policy, native Pi catalog publication, guarded request transport, response authentication buffering, and terminal error handling for the NEAR AI and Tinfoil extensions. This library is not a Pi extension and imports neither provider SDK.

`createTeeProvider` exposes a native provider, catalog initialization, policy selection and a content-free report. Default `public-builds` targets automatically authenticated public releases plus full hardware/serving-path checks; it blocks until a complete profile is implemented. `sdk` explicitly enables experimental routes with disclosed authorities. `approved` retains optional independent frozen-workload semantics, with no implemented profile. SDK acceptance never promotes a deployment into either stronger policy. [Policy and authority contract](../../docs/design.md).

`guardChatFetch` checks the final request after Pi payload conversion/hooks, fixes the model/endpoint/auth headers, and rejects unclassified fields, hosted tools and remote media URLs. `authenticateResponse` returns response headers promptly but releases bounded body bytes only after its verifier accepts the completion record. Cryptography belongs to the official provider adapters; a custom verifier is trusted local code, not provider-supplied evidence.

Adapters can return an owned `baseUrl` after canonical-model preflight; caller and cached model URLs cannot select it. Optional route model restrictions hide unsupported models and reject stale selections before attestation. `pinnedTlsFetch()` checks the hardware-attested SPKI on the exact TLS 1.3 socket before creating HTTP headers or sending a body. It sends once, does not follow redirects, and propagates cancellation. A real local TLS test proves that a wrong key receives zero HTTP requests; the ephemeral fixture requires `openssl`.

The library guards its own provider requests, not all Pi dispatches. Independent approval, a closed production trust set and protected-session enforcement remain unestablished. Tested with Pi AI 1.0.4.
