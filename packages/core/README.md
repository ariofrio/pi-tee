# @ariofrio/pi-tee-core

Shared policy, native Pi catalog publication, guarded request transport, response authentication buffering, and terminal error handling for the NEAR AI and Tinfoil extensions. This library is not a Pi extension and imports neither provider SDK.

`createTeeProvider` exposes a native provider, catalog initialization, policy selection and a content-free report. The default policy is `approved`; it blocks because this version implements no independently approved production profile. `sdk` is an explicit weaker policy with disclosed authorities. No SDK verification boolean promotes a deployment to Approved.

`guardChatFetch` checks the final request after Pi payload conversion/hooks, fixes the model/endpoint/auth headers, and rejects unclassified fields, hosted tools and remote media URLs. `authenticateResponse` returns response headers promptly but releases bounded body bytes only after its verifier accepts the completion record. Cryptography belongs to the official provider adapters; a custom verifier is trusted local code, not provider-supplied evidence.

The library guards its own provider requests, not all Pi dispatches. Independent approval, a closed production trust set and protected-session enforcement remain unestablished. Tested with Pi AI 1.0.4.
