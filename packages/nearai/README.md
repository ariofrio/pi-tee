# @ariofrio/pi-nearai

NEAR AI provider extension for Pi 1.0.4, requiring Node 24. Supports native API-key `/login nearai`, `NEARAI_API_KEY`, live chat/tool model discovery, Pi tool handling and usage, SDK encryption, and response-signature verification before text or tool calls are exposed.

Build from the repository's locked workspace, then load `dist/extension.js` with `pi -e`. The shared `@ariofrio/pi-tee-core` library is a dependency; it is not another extension. This package does not load Tinfoil.

Default `approved` policy hides models and blocks inference: no independently approved production profile is implemented. `PI_NEARAI_POLICY=sdk` or `/nearai policy sdk` explicitly accepts SDK-policy authorities. `/nearai policy approved` restores blocking and aborts active requests. In-session policy choices are not persisted. `/nearai status`, `/nearai models`, and `/nearai models refresh` show the report and refresh discovery. `PI_TEE_OFFLINE=1` disables startup discovery.

SDK policy enables attested gateway TLS, OHTTP and model field encryption, accepts only `UpToDate` CPU status, requires GPU evidence, and requires a model-serving response signature. The signature follows the shared model identity; it does not identify an independently approved serving instance. Responses are buffered in memory until verified, delaying visible output. Decrypted bodies are capped at 8 MiB and gateway network bodies at 32 MiB before SDK buffering; verification keeps additional copies. Remote media URLs, hosted tools and unclassified options are rejected.

Additional trust remains in Intel/NVIDIA verification and remote-verdict/JWKS policy, WebPKI key bootstrap, NEAR gateway/model release and key-service authorities, shared-key recipients, runtime deployment/mutation, download dependencies and model assets. Full guest-image appraisal, CPU–GPU association, exclusive key custody, deployment provenance and independent software approval are not established. Neither a closed production trust set nor protection across other Pi providers is claimed.

These limits cannot be closed solely by checking another report or matching a shared certificate/signature. A qualifying backend contract and independent deployment inventory are required. [Model signer contract](https://docs.near.ai/cloud/verification/cloud-api/model-attestations), [SDK Intel fields](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/utils/intel.ts#L101).

NEAR refuses Bun and Node 22 in this release. Browser OAuth and independently approved deployment profiles are not implemented. Provider credentials were unavailable for authenticated live inference validation.
