# Owned portable TLS transport

This Go helper owns one TLS 1.3 connection and one inference POST. It uses only the Go standard library. The TypeScript adapter is [pinnedTlsHelperFetch](../../packages/core/src/pinned-tls-helper.ts); the current production providers still use their existing transport. This helper is being qualified as its portable replacement.

The parent first sends the endpoint and attested SHA-256 SPKI fingerprint. The helper completes TLS and compares the peer's public key before announcing readiness. Only then does the parent send headers and the body. Attested SPKI replaces WebPKI authorization, as in the existing transport. HTTP never creates another socket, follows a redirect, pools a connection or retries a request. Parent EOF closes the connection; aborting or cancelling the response closes the pipes and terminates the helper.

The adapter requires an absolute artifact path and an expected SHA-256 digest from trusted adapter code. It checks the binary, executes a private snapshot, supplies no inherited credentials/proxy settings, bounds request/control frames and streams response chunks with backpressure. It removes the snapshot after child exit. No credentials, request bodies or responses are written to disk. Failures expose fixed codes only. The caller must retain model/admission/expiry checks, response authentication, total response bounds and its send-once guard.

## Pipe protocol

Each frame is a one-byte kind, a four-byte unsigned big-endian payload length, then the payload. JSON controls have a 64 KiB cap; the request body has the shared 16 MiB cap and is base64-encoded inside its request control. Body frames contain up to 32 KiB of raw bytes.

| Kind | Direction | Payload |
| --- | --- | --- |
| 1 | Parent → helper | JSON `endpoint`, `fingerprint`; contains no credentials or body |
| 2 | Helper → parent | Empty; the exact TLS socket passed the attested-key check |
| 3 | Parent → helper | JSON `headers`, base64 `body` |
| 4 | Helper → parent | JSON HTTP `status`, multi-value `headers` |
| 5 | Helper → parent | Response body chunk |
| 6 | Helper → parent | Empty; response body ended normally |
| 7 | Helper → parent | Fixed terminal error code |

The input pipe stays open throughout response consumption. EOF is cancellation. A new child is required for a different request; no reconnect or fallback protocol exists.

## Maintainer validation

Use Node 24 and Go 1.26.6. `npm run check:pinned-tls` runs the real Go socket tests, builds the current platform binary twice, compares hashes and tests the Node adapter against a separate TLS server. `npm run check:pinned-tls -- --bun` runs the same adapter cases under Bun. These tests cover key/artifact rejection before HTTP, success, streaming, redirect return, a consumed request with a dropped response, and cancellation. `go test -race ./...` in this directory additionally checks concurrency.

The live Pi harness accepts `--portable-tls-candidate` with `PI_TEE_PINNED_TLS_TEST_HELPER` to exercise the new transport after the existing complete Gemma appraisal. `PI_TEE_LIVE_PI_BINARY` selects an absolute standalone Pi binary path; without it, the harness uses the Node CLI. Both are opt-in synthetic inference tests. The candidate does not change production admission or its GPU verifier requirements.

Cross-compilation and one host's tests do not qualify every platform. Reviewed artifact packaging, target execution, final route integration and independent review remain release requirements; [portability status](../../docs/portable-verification.md).
