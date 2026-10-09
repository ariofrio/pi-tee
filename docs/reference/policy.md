# Policy reference

Set `PI_TEE_POLICY=<position>[,axis=value…]` for all extensions. Provider-scoped session commands accept the same syntax. The shipped default is `public-builds,egress=metadata`; an explicit bare position uses its own defaults below. Level definitions are in the [security model](../security-model.md).

## Position defaults

| Position | code | host | gpu | egress | Trust permitted |
| --- | --- | --- | --- | --- | --- |
| `public-builds` | public-release | current | verified | none | Neither provider nor host |
| `public-builds-trust-host` | public-release | stale | unchecked | none | Host |
| `trust-provider` | provider-controlled | current | verified | any | Provider |
| `trust-provider-and-host` | provider-controlled | stale | unchecked | any | Provider and host |

Public-build positions also default to `build=publisher-workflow,review=none`. All positions default to `verifier=local`. Security-axis values below run strongest to weakest; verifier values are alternative appraisal choices.

| Axis | Recognized values |
| --- | --- |
| code | `public-release`, `fixed-private`, `provider-controlled` |
| host | `current`, `outdated-firmware`, `stale` |
| gpu | `verified`, `gaps`, `unchecked` |
| egress | `none`, `metadata`, `any` |
| build | `reproduced-off-github`, `reproduced`, `publisher-workflow`, `signed` |
| review | `pinned`, `window`, `none` |
| verifier | `local`, `nras` |

Only `build=publisher-workflow` and `review=none` are implemented. Other build/review values fail clearly as not yet supported, including `build=signed`. The router's B4 component evidence does not implement B4 route-wide public admission. No current route is X1; bare `public-builds` therefore admits none.

## Forced values and categories

Code below `public-release` forces `egress=any` and prohibits `build` and `review`. `host=stale` forces `gpu=unchecked`. The name must match both categories: public-build names require public code; provider-trust names require private or provider-controlled code. Host-excluding names require `host=current,gpu=verified`; host-trusting names require at least one weaker value. Contradictions, unknown values, duplicate axes and malformed settings are rejected with an explanation. These rules leave 35 combinations of the four axes.

With `gpu=unchecked`, `verifier=nras` warns that it has no admission effect. NEAR, Chutes and Privatemode remain G3 and never contact NRAS. Opt-in NRAS for Tinfoil uses the [same GPU gates and added service trust](../security-model.md#admission-and-selection).

## Examples

Use the [provider guide's admission table](../providers.md) for supported routes. These settings express thresholds rather than permanent model ratings:

```text
public-builds,egress=metadata
public-builds-trust-host,egress=metadata,host=outdated-firmware,gpu=verified
trust-provider-and-host,host=current
trust-provider-and-host,code=fixed-private
```

## Migration

The former default `public-builds` maps to `public-builds,egress=metadata`. Explicit bare `public-builds` now requests X1. Removed `sdk` returns a migration error directing users to `trust-provider-and-host`; adding `host=current` preserves outdated-instance rejection and excludes the stale Tinfoil router. Removed `approved` maps conceptually to `public-builds,review=pinned`, which is unsupported, not an accepted alias.

`PI_NEARAI_POLICY`, `PI_TINFOIL_POLICY`, `PI_NEARAI_ROUTE` and `PI_TINFOIL_ROUTE` return migration errors. Use `PI_TEE_POLICY` and automatic route selection. Policy changes abort active requests, affect only the named provider when issued as a command, and are not persisted.

Implementation: [parsePolicy()](../../packages/core/src/policy.ts), [assessRoute()/compareRoutes()](../../packages/core/src/security.ts). A qualifying weaker route may be selected only under the user's existing thresholds; verification failure never relaxes them.
