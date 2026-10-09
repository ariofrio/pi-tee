# Provider guide

These are installed adapter capabilities, checked against the merged implementation. Levels apply only after the current request's checks pass. Instances can differ; [dated results](evidence/README.md) do not promise fleet availability. Definitions are in the [security model](security-model.md), with complete [policy syntax](reference/policy.md).

| Provider / route | Verified levels | Tightest policy for the stated case |
| --- | --- | --- |
| [Tinfoil direct / billing gateway](providers/tinfoil.md), current protected worker | A1 H1 G1 X2 B3 S3 | `public-builds,egress=metadata` |
| Tinfoil Genoa worker below local floors, otherwise G1 | A1 H2 G1 X2 B3 S3 | `public-builds-trust-host,egress=metadata,host=outdated-firmware,gpu=verified` |
| Tinfoil router | A3 H3 G3 X3 | `trust-provider-and-host` |
| [NEAR direct / gateway](providers/nearai.md), current CPU evidence | A3 H1 G3 X3 | `trust-provider-and-host,host=current` |
| NEAR fresh outdated/below-floor CPU evidence | A3 H2 G3 X3 | `trust-provider-and-host,host=outdated-firmware` |
| [Chutes instance-key route](providers/chutes.md), current CPU evidence | A3 H1 G3 X3 | `trust-provider-and-host,host=current` |
| Chutes fresh outdated/below-floor CPU evidence | A3 H2 G3 X3 | `trust-provider-and-host,host=outdated-firmware` |
| [Privatemode mesh](providers/privatemode.md) | A2 H3 G3 X3 | `trust-provider-and-host,code=fixed-private` |

No route currently establishes X1. Tinfoil's authenticated G2 gaps require a policy admitting those actual levels; the table's G1 examples do not imply all workers qualify. Intel `OutOfDate` Tinfoil public workers are unavailable under every policy because the pinned verifier rejects them.

All four providers support native key login, tool chat, reasoning, usage and cancellation. NEAR, Tinfoil and Chutes discover supported chat/tool models; Privatemode starts with a shipped three-model catalog and restricts credentialed refresh to those IDs. Prices and capabilities are provider claims. Missing prices are labeled, and NEAR pricing tiers beyond base costs are not modeled.

The [ecosystem survey](provider-survey.md) covers prospective providers separately. It is not an installed-adapter support matrix.
