# pi-nearai

NEAR AI provider extension for Pi 1.0.4, requiring Node 24. Supports native API-key `/login nearai`, `NEARAI_API_KEY`, live chat/tool model discovery, Pi tool handling and usage, SDK encryption, and response-signature verification before text or tool calls are exposed.

Build from the repository's locked workspace, then load `dist/extension.js` with `pi -e`. The shared `pi-tee-core` library is a dependency; it is not another extension. This package does not load Tinfoil.

Default `public-builds` policy hides models and blocks inference because NEAR's complete profile is not implemented. Some missing checks are client work; session binding and deployment/key/runtime qualification also need backend support or verifiable evidence. [What is missing and who can fix it](../../docs/nearai-status.md). `PI_NEARAI_POLICY=sdk` or `/nearai policy sdk` accepts experimental route assumptions. `/nearai policy public-builds` restores the default; `approved` has no implemented profile. Policy changes abort active requests and are not persisted. `/nearai status`, `/nearai models`, and `/nearai models refresh` report status and refresh discovery. `PI_TEE_OFFLINE=1` disables startup discovery.

Separately, discovery defaults to TEE-only. Public per-model metadata must match the requested ID and declare `providerType: "vllm"` plus `attestationSupported: true`; this is a capability claim, not attestation verification. Non-TEE and unknown models are hidden. Set `PI_NEARAI_MODEL_VISIBILITY=all` at startup or use `/nearai models all` to display them with an inference-blocked label; `/nearai models tee` restores the default. Session commands do not persist the setting. Showing a non-TEE model does not enable inference: it fails before SDK setup. Public-build and Approved policies currently hide all picker models. Offline snapshots without capability data are treated as unknown.

SDK policy enables attested gateway TLS, OHTTP and model field encryption, accepts only `UpToDate` CPU status, requires GPU evidence, and requires a model-serving response signature. The signature follows the shared model identity; it does not identify an independently approved serving instance. Responses are buffered in memory until verified, delaying visible output. Decrypted bodies are capped at 8 MiB and network bodies at 32 MiB before SDK buffering; verification keeps additional copies. Remote media URLs, hosted tools and unclassified options are rejected.

Additional trust remains in Intel/NVIDIA verification and remote-verdict/JWKS policy, WebPKI key bootstrap, NEAR gateway/model release and key-service authorities, shared-key recipients, runtime deployment/mutation, download dependencies and model assets. Full guest-image appraisal, CPU–GPU association, exclusive key custody, deployment provenance and independent software approval are not established. Neither a closed production trust set nor protection across other Pi providers is claimed.

Another quote or matching shared signature cannot establish an exclusive serving session. The [NEAR assessment](../../docs/nearai-status.md#why-a-valid-quote-and-signature-are-insufficient) explains the ambiguity and the backend binding or key-recipient restrictions needed to resolve it.

NEAR refuses Bun and Node 22 in this release. Browser OAuth and independently approved deployment profiles are not implemented. Both [observed gateway instances](../../docs/nearai-status.md#how-many-gateways-are-affected) returned `OutOfDate` TDX status; the gateway route rejects them under the required `UpToDate` policy. Fleet-wide status is unknown.

Set `PI_NEARAI_POLICY=sdk PI_NEARAI_ROUTE=direct` before loading the extension to use the experimental GLM candidate, `z-ai/glm-5.3-flash`. The route restricts the picker and preflight to that model. [Direct transport](src/direct.ts) and [owned channel](src/direct-channel.ts) use one TLS 1.3 connection for fresh quote, encrypted OHTTP inference and signature lookup. Quote-bound SPKI approval precedes credentials; WebPKI validation also applies. Reconnection, a second inference POST and arbitrary paths are rejected. Abort or a terminal result closes the channel. CPU `UpToDate`, required GPU evidence, field encryption, OHTTP and the response-signature barrier remain required.

This remains SDK policy. Passing the direct-route tests does not qualify the public-build profile. [Evidence and validation](../../docs/direct-access.md#near-direct-route-and-evidence), [live Pi harness](../../scripts/live-pi.ts).

Written by Codex.
