# pi-nearai

NEAR AI extension for Pi 1.0.4: native `/login nearai`, `NEARAI_API_KEY`, live chat/tool discovery, reasoning, tools/usage, encrypted inference and response signatures. Build in the locked Node 24 workspace and load `dist/extension.js` with `pi -e`. It depends on `pi-tee-core` and does not load Tinfoil's SDK. Stored Pi credentials take precedence over environment keys; browser OAuth is not implemented.

## Policy and routes

Both providers use `PI_TEE_POLICY`. The shipped `public-builds,egress=metadata` admits no NEAR models: serving/runtime/key custody is provider-controlled (A3), GPU coverage is incomplete (G3), and handling limits cannot be established (X3). Use `trust-provider-and-host` to admit those gaps, or `trust-provider-and-host,host=current` to require fresh CPU evidence at pi-tee's local floors. [Positions and thresholds](../../docs/security-model.md), [NEAR assessment](../../docs/nearai-status.md).

For GLM-5.3 Flash, the adapter can select the direct route; other supported models use the gateway. The client appraises qualifying routes before the prompt and compares code, host, GPU and egress. H1 requires Intel `UpToDate`, TDX SVN components at least `[3,1,2]`, and verified TCB/QE collateral editions at least 20. Fresh evidence below floors, including unreadable floor values or `OutOfDate`, rates H2. Gateway rating uses its weakest checked CPU component. Signatures, revocation, nonce/key binding and SDK production restrictions remain required.

GPU evidence is optional local status detail. Even authentic reports do not establish complete serving coverage, so NEAR remains G3 and GPU failures do not gate admission. Neither route contacts NRAS, including when a policy sets `verifier=nras`; with `gpu=unchecked` the setting warns that it has no admission effect. Status includes authenticated device/mode/firmware observations when local appraisal succeeds, and distinguishes failed diagnostics from evidence.

The [direct channel](src/direct-channel.ts) owns one WebPKI-authenticated TLS 1.3 socket for fresh evidence, OHTTP inference and signature lookup. Attested SPKI approval precedes credentials, and reconnect, repeat inference POSTs and arbitrary paths are rejected. It supports Node 24 and Bun-compiled Pi. The SDK gateway remains Node-only. Both routes retain field encryption/OHTTP and buffer bounded responses until a model-serving signature verifies; shared signing keys do not identify exclusive serving-instance custody. Decrypted bodies are capped at 8 MiB and encrypted/network bodies at 32 MiB.

`PI_NEARAI_POLICY` and `PI_NEARAI_ROUTE` are removed with migration errors. Removed `sdk` maps to `trust-provider-and-host`; `approved` points to pinned review, which is not yet supported. `/nearai policy <position>[,axis=value…]` aborts active requests and changes only this provider in the current session. `/nearai status` shows actual levels, trust, gaps, commitments and route choices. Commitments are displayed without gating admission or claiming verified deployed retention behavior.

## Discovery and scope

Discovery defaults to TEE-only: per-model metadata must match the model, declare attestation support, and use the supported `vllm` protocol. Chutes declarations remain separate from unavailable SDK transport. `/nearai models all` or `PI_NEARAI_MODEL_VISIBILITY=all` shows labeled unsupported/unknown entries without enabling inference; `/nearai models tee` restores filtering. `/nearai models refresh` forces refresh; `PI_TEE_OFFLINE=1` skips startup network discovery and restores snapshots. Session choices do not persist.

NEAR deployment, shared-key recipients, KMS and runtime inputs remain trusted. An extra quote or matching shared signature cannot establish exclusive serving identity. These extensions protect their own requests; other providers, extensions and tools can access the conversation. [Live harness](../../README.md#validation).

Written by Codex.
