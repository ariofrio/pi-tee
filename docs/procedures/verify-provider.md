# Qualify a provider

Use the [security model](../security-model.md), [hardware policy](../reference/hardware-policy.md), [production inventory obligations](../../SECURITY.md#required-closed-inventory) and provider-specific contract. Source inspection, fixture replay and package loading establish narrower facts than live qualification.

| Check | Required evidence / interpretation |
| --- | --- |
| Scope and recipient inventory | Exact client/dependency pins, model/route, all decrypting/key-release/shared-key recipients, administrators and mutable runtime inputs |
| CPU authenticity/freshness | Manufacturer signatures, production/debug restrictions, valid collateral/revocation, unpredictable client nonce and authenticated key/report binding |
| Software and runtime | Release identities/workflows, authenticated boot/config/OCI/model inputs, enforced input checks and key lifetime; data weights versus executable loaders distinguished |
| GPU protection | Every serving device, signed references/revocation, CPU binding, complete coverage, protected mode/channel/fabric and applicable floors |
| Dispatch | Native SDK/network seam observes no content before admission; final hooks cannot override payload/model/endpoint/auth; actual socket or sealed-key binding |
| Output | Real signature/AEAD authentication before completion or executable tools; bounded buffering/framing, substitution/truncation/replay negatives |
| Failure/cancellation | Wrong nonce/key/root/workflow/digest, stale/future/revoked evidence, incomplete coverage, runtime mutation and reconnect/resend rejected; local abort correctly acknowledged |
| Result | Observed levels and gaps under the same thresholds, rejected cases retained, no mock used to qualify deployment, independent review before production enablement |

Run [CONTRIBUTING's required checks](../../CONTRIBUTING.md). Supply private fixtures when available and report skips. [Fixture provenance](../../tools/tinfoil-public-build/testdata/README.md) distinguishes offline signatures from current freshness. Then use [live validation](live-validation.md) for its explicit inference scope, preserving evidence per the [record template](../evidence/README.md#recording-and-maintaining-observations).

New authorities, verifier roots/pins, firmware floors, runtime/key-custody contracts and SDK/Pi behavior require review and affected requalification. Do not substitute one successful worker for a fleet claim or assume old reviews cover later code.
