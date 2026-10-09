# NEAR AI

Load `packages/nearai/dist/extension.js` from the [locked checkout](../quick-start.md), then `/login nearai`. The API-key environment fallback is `NEARAI_API_KEY`.

## Routes and admission

Direct and SDK gateway routes remain A3/G3/X3. Fresh CPU evidence rates H1 or H2 using the [shared TDX floors](../reference/hardware-policy.md#intel-tdx). For H1, the tightest policy is `trust-provider-and-host,host=current`; supported outdated instances require `host=outdated-firmware`. The default public-build policy admits no NEAR route.

NEAR's operator can deploy serving software at arbitrary Git refs through a root-equivalent compose-manager. Workloads can obtain TLS and app-wide encryption/signing keys; a quote authenticating past actions does not bound the next deployment. The client cannot establish an immutable public serving release or exclusive instance custody. [Pinned runtime/KMS investigation](../evidence/nearai/runtime-key-custody.md). Closing this gap needs server-side release authorization, workload-bound key derivation and a freeze/rotation contract.

Both routes take the weakest CPU rating across every checked attestation, including other model instances sharing keys and the CPU-only gateway when used. A current serving instance can therefore fail `host=current` because another recipient is H2. Optional local GPU diagnostics can provide authenticated device/mode/firmware details, but incomplete serving coverage remains G3; diagnostic failure cannot gate admission. Neither route contacts NRAS.

Each route owns one WebPKI-authenticated TLS 1.3 socket per request for fresh evidence, OHTTP inference and signature lookup; the gateway's socket also carries model metadata and model evidence for the requested model. The SPKI that the fresh quote binds must be that socket's before the sealed request is written, and reconnect, repeat inference POSTs and arbitrary paths fail. Direct sends credentials only after approval. NEAR's gateway requires the API key for its own evidence, so the gateway route sends it over WebPKI before approval, as NEAR's SDK does. Both routes support Node and Bun. Gateway replicas can share one TLS key and signer, so the socket binding does not identify one gateway instance ([gateway socket record](../evidence/nearai/gateway-socket.md)). Both retain field encryption/OHTTP and release bounded completion/tool bytes only after response-signature verification. A shared signing key authenticates a key holder, without establishing an exclusive serving instance.

## Discovery and diagnosis

TEE-only visibility is the default: matching per-model metadata must declare attestation support; gateway transport requires `providerType: "vllm"`. Direct candidates are the intersection of tool-capable catalog models and the endpoint registry. Registry-only models are ignored, hostnames are strictly validated, and network discovery must complete before direct can be selected. Endpoint availability remains in memory; offline snapshots cannot restore direct endpoints. [Discovery implementation and dated qualification](../near-direct-discovery.md).

`/nearai models all` shows labeled unsupported/unknown entries without enabling inference; `models tee` restores filtering. Non-TEE entries and unsupported Chutes declarations cannot dispatch through this SDK. NEAR-backed Chutes gateway plaintext is a distinct recipient, without an implemented client-to-Chutes path here; use the separate [Chutes adapter](chutes.md) with its own credentials.

`/nearai status` reports actual levels, trust, gaps, commitments, route decisions and skipped endpoints. TLS/WebPKI rejection keeps its classified code separately from connection failure. Catalog visibility does not change policy. Use the shared [commands/settings](../reference/commands-settings.md) and [limits](../reference/support-limits.md).

Commitments do not gate admission. The dated investigation records no contractual no-retention promise in ToS/DPA, source-level Responses transcript storage without TTL versus no Chat Completions transcript persistence (deployment unverified), a no-training promise/ISO 27001 listing without a public SOC 2 report, and incomplete Chutes sub-processor coverage. [Observation record](../evidence/nearai/commitments.md).
