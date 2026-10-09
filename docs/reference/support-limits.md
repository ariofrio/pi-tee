# Support and limits

Use the locked Node 24 workspace and Pi 1.0.4. Local NVIDIA and Tinfoil CPU/release verification ships as hash-checked WASM; users need no compiler, container or native helper. Qualification is narrower than an architecture target.

| Scope | Support / qualification |
| --- | --- |
| Desktop WASM hosts and owned TLS transport | [Verifier CI](../../.github/workflows/wasm-verifiers.yml) covers Linux/macOS/Windows, x64/ARM64, Node and Bun; these checks do not send inference |
| Tinfoil public direct and billing gateway | Node and Bun live Pi suites are recorded for the stated models/revisions in [evidence](../evidence/README.md#tinfoil) |
| NEAR direct, Chutes, Privatemode | Node/Bun adapter checks and sampled live suites are in [provider evidence](../evidence/README.md#other-providers) |
| NEAR SDK gateway | Node path; direct is the portable Node/Bun path |
| Tinfoil router | Uses the public-direct WASM verifier and owned transport; Node live appraisal and inference recorded in the [router appraisal record](../evidence/tinfoil/router-appraisal.md). No Bun-compiled Pi router suite has been run since the SDK was removed |
| Android/Termux | Client target; emulator credential-free appraisal recorded in [portability evidence](../evidence/client/portable-verification.md). No Android live Pi suite was established |

## Payload and lifetime bounds

| Bound | Value / enforcement |
| --- | --- |
| Guarded request JSON | 16 MiB; [transport constants](../../packages/core/src/transport.ts) |
| Bounded plaintext response where enforced by shared response/EHBP guards | 8 MiB; NEAR buffers until signature authentication |
| Encrypted/network response body | 32 MiB; owned HTTP framing additionally bounds headers/trailers and overhead |
| Whole provider request | Default/max 600 seconds; a smaller caller timeout applies; [run()](../../packages/core/src/provider.ts) |
| Tinfoil public direct discovery/appraisal | At most eight reachable candidates; 16 concurrent TCP probes, 3 seconds each; 120-second per-candidate cap; [selection](../../packages/tinfoil/src/public-session.ts) |
| Tinfoil admission | Minimum of check +60 seconds, challenge +300 seconds and both witness timestamps +7 days; rechecked at dispatch/TLS handoff |
| Tinfoil immutable cache | 96 MiB / 128 entries; [cache](../../packages/tinfoil/src/public-build.ts) |
| Chutes admission | Minimum of invocation-token expiry and fresh challenge +60 seconds; rechecked after hooks/encryption |
| Privatemode bootstrap/admission | 60 seconds; isolated worker disposed on cancellation/error; network/decrypted chunks use backpressure |

Unsupported request fields, hosted tools, transport overrides and remote media are rejected after Pi payload hooks. Inline base64 PNG/JPEG/WebP/GIF is the allowed image form. Requests cannot enable provider storage (`store` may only be false). Every text/tool output crosses signature or encrypted-frame authentication before exposure. Limits address memory/availability, not output correctness.

## Errors, retries and cancellation

Direct owned transports send once and reject redirects, reconnects and resends. Chutes invocation owns its WebPKI socket so HTTP 421 cannot trigger a runtime resend. The Tinfoil router also sends once: a key rotation ends the dispatch. Pi provider retries are disabled; fixed terminal error codes also suppress Pi 1.0.4 turn/summarization retry paths. [safeFailure()](../../packages/core/src/provider.ts).

Cancellation aborts local work/readers and disposes sessions, keys and verifier workers. A local acknowledgement or live-delta abort does not measure remote generation-stop timing. Availability, truthful billing, traffic analysis, output correctness and local compromise remain outside the [security boundary](../../SECURITY.md).
