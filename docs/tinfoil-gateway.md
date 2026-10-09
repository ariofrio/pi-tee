# Tinfoil billing gateway

The billing gateway is an opaque relay for DeepSeek V4.1 Flash and GLM-5.3. Each dispatch uses the same [worker appraisal](../packages/tinfoil/src/worker-appraisal.ts) as direct access: fresh CPU evidence, public guest/workload/container/runtime provenance, key custody, local CPU floors and CPU-bound GPU checks. Successful checks establish the same A1/H1/G1/X2/B3/S3 levels; permitted weaker hardware levels follow the selected policy. Discovery never authorizes a request.

## Selection and credential boundary

The client reads the untrusted [gateway catalog](https://inference-gateway.tinfoil.sh/catalog), bounds it and admits only the two local model/repository mappings and valid worker hosts. Direct is preferred whenever it qualifies, because fewer parties receive the API key and metadata. The gateway is appraised only when no direct worker qualifies. `/status` records the direct rejection or preference, the chosen route and its actual levels. [Selection](../packages/tinfoil/src/gateway.ts), [shared enforcement](../packages/core/src/provider.ts).

TLS 1.3 terminates at the unattested gateway, authorized by normal WebPKI hostname/certificate checks. It receives the API key, model, headers and worker hostname. This differs from direct's attested-socket credential rule and is disclosed separately from the axes. The gateway has no worker HPKE private key and never receives a plaintext body. Billing truthfulness and availability are outside the model. The named public releases remain trusted to preserve the [worker key-custody contract](tinfoil-public-profile.md).

Gateway admission uses a distinct profile/policy digest that includes the direct appraisal authority plus the gateway endpoint, WebPKI transport, seal, metadata recipient and send-once rules. The worker's authority and appraisal are unchanged. [Admission identity](../packages/tinfoil/src/gateway.ts).

## Protocol facts

Sources were checked at tinfoil-go [`502b8e2665bf1b67921c3b1087eade39059b30dc`](https://github.com/tinfoilsh/tinfoil-go/tree/502b8e2665bf1b67921c3b1087eade39059b30dc), the head of [tinfoil-go #188](https://github.com/tinfoilsh/tinfoil-go/pull/188) (`46f9219a0e5d5cc99287c934d7cffbb0b0f8e3df`), and [tinfoil-proxy #43](https://github.com/tinfoilsh/tinfoil-proxy/pull/43) (`204a7a0229391f51a8e4991763a7b011ecf1364e`).

- The [catalog endpoint](https://github.com/tinfoilsh/tinfoil-go/blob/502b8e2665bf1b67921c3b1087eade39059b30dc/gateway_catalog.go#L15) is `/catalog`. The live read on 2026-10-09 returned only `deepseek-v4-1-flash` and `glm-5-3`; Gemma is excluded.
- Evidence is relayed through `GET /.well-known/tinfoil-attestation?nonce=<fresh hex nonce>&enclave=<worker host>`. The client verifies the returned bytes rather than trusting the gateway. [Relay URL](https://github.com/tinfoilsh/tinfoil-go/blob/502b8e2665bf1b67921c3b1087eade39059b30dc/internal/fetch/fetch.go#L90-L113), [gateway handle](https://github.com/tinfoilsh/tinfoil-go/blob/502b8e2665bf1b67921c3b1087eade39059b30dc/gateway.go#L78-L95).
- Inference carries `X-Tinfoil-Model`, `X-Tinfoil-Seal: <worker host>` and `X-Tinfoil-Enclave-Url: https://<worker host>`. EHBP encrypts the body to the worker's quote-bound HPKE key. [Seal and model headers](https://github.com/tinfoilsh/tinfoil-go/blob/502b8e2665bf1b67921c3b1087eade39059b30dc/seal_transport.go#L23-L31), [enclave URL and encryption](https://github.com/tinfoilsh/tinfoil-go/blob/502b8e2665bf1b67921c3b1087eade39059b30dc/enclave_transport.go#L60-L81). The [proxy forwards only inference headers](https://github.com/tinfoilsh/tinfoil-proxy/blob/204a7a0229391f51a8e4991763a7b011ecf1364e/proxy.go#L41-L43) because the gateway is unattested.
- The seal header is a routing instruction, not cryptographic authorization of a hostname. The worker's own appraised HPKE key supplies the binding: redirecting ciphertext to another worker cannot make that worker accept it. Substituted evidence cannot alter a CPU-bound key section without rejection; substituting an entirely valid worker document would seal to that document's appraised key, never a gateway-selected unauthenticated key. Responses use the request's HPKE exporter context, so another worker or another dispatch cannot authenticate replacement text. [Shared encrypted transport](../packages/tinfoil/src/direct.ts), [crypto negatives and positive control](../tests/tinfoil-gateway.test.ts).

## 412, responses and limits

A 412 means the sealed worker is unavailable. pi-tee fails the dispatch without automatic re-selection or resend. A later request obtains fresh evidence and a new sealing context under the same policy. This deliberately chooses the spec's permitted terminal behavior; the [Go SDK](https://github.com/tinfoilsh/tinfoil-go/blob/502b8e2665bf1b67921c3b1087eade39059b30dc/seal_transport.go#L175-L208) instead follows bounded 412 reroutes. Other non-200 responses, redirects, rotation errors and dropped connections are terminal too. Pi retries remain disabled.

Gateway and direct share [socket framing](../packages/core/src/pinned-tls.ts) and [body limits](../packages/core/src/transport.ts): 16 MiB request, 32 MiB encrypted response and 8 MiB plaintext response; stalled receivers are bounded on Node and Bun. Only self-delimiting HTTP responses are accepted. Streaming text and tool output pass EHBP authentication before exposure. Tests cover another worker's key, replayed nonce, swapped key evidence, a 412 loop, response substitution/tampering/truncation, untrusted TLS and direct preference. No NRAS calls are required.

## Validation

`npm run check`, both package/load smokes, the Go helper checks and Bun transport/crypto tests run on the branch. Private relay evidence negatives use `PI_TEE_GATEWAY_TEST_EVIDENCE`; evidence bytes remain outside the repository. The [live Pi harness](../scripts/live-pi.ts) accepts `tinfoil <model> --public-builds --gateway` to exercise the production gateway adapter, and `PI_TEE_LIVE_PI_BINARY` selects the Bun-compiled Pi. Live qualification is pending the base branch's approved platform-authority update; no inference was sent before that gate passed.

Written by Codex.
