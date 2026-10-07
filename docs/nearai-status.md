# Why NEAR public builds are not enabled

**NEAR support is implemented. Its stronger `public-builds` mode is not.** The experimental direct GLM route works in Pi. Public-build mode rejects inference pending client checks, deployment investigation and backend bindings. It can be enabled once the requirements below are met.

This assessment covers the [inspected SDK revision](https://github.com/nearai/inference-sdk/tree/b9930893a9f560e66898e1616111c5ac2241686c) and [tested routes](direct-access.md#near-direct-route-and-evidence). It is our source-based assessment, not a NEAR-published vulnerability list or a claim about every deployment.

## What already works

`PI_NEARAI_POLICY=sdk PI_NEARAI_ROUTE=direct` selects `z-ai/glm-5.3-flash`. The extension verifies fresh Intel evidence, requires NVIDIA GPU evidence, checks the quote-bound TLS public key on one connection, encrypts inference and verifies the model's response signature before displaying text or executing tools. It rejects reconnects and a second inference POST. [Adapter](../packages/nearai/src/direct.ts), [channel](../packages/nearai/src/direct-channel.ts), [validation](direct-access.md#near-direct-route-and-evidence).

The route passed login, completion, tools, reasoning, usage and cancellation tests. The default gateway's observed `OutOfDate` rejection is separate: the direct GLM sample passed `UpToDate`, while the sampled Qwen endpoint did not.

## Why a valid quote and signature are insufficient

NEAR [documents shared model signing keys](https://docs.near.ai/cloud/verification/cloud-api/model-attestations), including across instances with different measured configurations. A response signed by that shared key therefore does not identify which measured instance served it.

The inspected SDK's [TLS binding](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/core/attestation-common.ts#L57) authenticates the signing identity, TLS public-key fingerprint and client nonce. It does not authenticate a value unique to the client's TLS session.

Suppose acceptable instance A and another instance B hold the same TLS key. B can terminate the client's connection, ask A for a fresh quote using the client's nonce, and return that quote. Both the nonce and TLS-key check pass. A shared response signature does not resolve the ambiguity. Checking another fresh quote cannot distinguish these cases.

This is a protocol limitation **when keys are shared with recipients outside the accepted policy**. It is not evidence that such an attack occurred. Shared keys could be acceptable if an authenticated key-release policy confines every holder to acceptable environments; we have not established that policy or the actual production TLS-key sharing scope.

## Remaining work and who can do it

| Requirement | Status | Needed work |
| --- | --- | --- |
| Authenticate the guest OS/boot configuration | Unfinished client work and artifact mapping | Compare boot measurements (MRTD and RTMR0–2) with authenticated public guest builds. The [SDK adapter](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/utils/intel.ts#L101) does not expose/appraise them. A guest-reported OS hash cannot replace this check. |
| Constrain the measured application configuration | Unfinished client work | The SDK already [binds `app_compose` to MRCONFIGID](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/core/attestation-common.ts#L188). Add a policy for acceptable images, downloads, privileges, mounts, egress and mutation. |
| Appraise GPU firmware, mode and revocation in detail | Unfinished client work | The [SDK consumes NVIDIA's overall signed remote verdict](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/utils/nvidia.ts#L53). Add the detailed manufacturer appraisal and an explicit verifier/key policy. |
| Bind evidence to the serving session | Backend binding or verifiable recipient restrictions needed | Use instance-exclusive attested session keys, or have the measured TLS terminator quote its own [TLS exporter](https://www.rfc-editor.org/rfc/rfc9266.html#section-2). Alternatively establish that every shared-key holder satisfies the policy. The client cannot invent a missing server binding. |
| Bind the GPU and protected compute path to the attested CPU environment | Backend evidence/contract needed | The [quoted layout](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/core/attestation-common.ts#L57) does not commit to GPU evidence. Equal nonces establish freshness, not which environment uses the GPU. Establish an authenticated association and enforced protected channel; a GPU hash alone would not prove the channel. |
| Establish key release, administrators and runtime integrity | Deployment investigation; changes may be necessary | Identify the actual KMS, its deployed code/policy, governing parties, recipients and mutation rules. Public [KMS source](https://github.com/nearai/near-kms/blob/dd792a9fa228d33c6dbe615646242d20e9d876a4/README.md) is not proof of which policy production runs. |

The inspected [deployment recipe](https://github.com/nearai/cvm-compose-files/blob/cda2032fa8f8638639d858703b6de4d76c2118e8/prod/dsv4-qwen36-gemma4.yaml#L254) also downloads models using unpinned package tooling and contains privileged/mutable services. Public source and a measured compose file do not authenticate every byte downloaded later or ensure keys are retired before a runtime change. Qualify an existing deployment that enforces these properties, or change the server to authenticate those inputs and constrain mutation. This recipe is not proof that the tested GLM worker uses the same configuration.

## What would enable public builds

Identify the tested worker's guest artifacts, runtime, key-release policy and recipients. Implement the client checks. Establish session/GPU/runtime contracts through verifiable deployment evidence or server changes, then test the complete route through Pi and independently review it before enabling the profile.

Research can resolve deployment unknowns; client code can add boot/config/GPU checks. Neither alone supplies the missing serving-session proof. The [independent review](reviews/pi-tee-public-build-opus-review.md#near-what-a-client-can-and-cannot-solve) also distinguishes client work from backend requirements.

This policy would accept releases from named public publishers and workflows automatically, as Tinfoil's does. Independent review of each NEAR release and a maintained deployment-pin catalog are not requirements.

Written by Codex.
