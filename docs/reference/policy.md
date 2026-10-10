# Policy reference

Set `PI_TEE_POLICY=<position>[,axis=value…]` for all extensions. Provider-scoped session commands accept the same syntax. The shipped default is `public-builds,egress=metadata`; an explicit bare position uses its own defaults below. Level definitions are in the [security model](../security-model.md).

## Position defaults

| Position | code | host | gpu | egress | Trust permitted |
| --- | --- | --- | --- | --- | --- |
| `public-builds` | public-release | current | verified | none | Neither provider nor host |
| `public-builds-trust-host` | public-release | stale | unchecked | none | Host |
| `trust-provider` | provider-controlled | current | verified | any | Provider |
| `trust-provider-and-host` | provider-controlled | stale | unchecked | any | Provider and host |

Public-build positions also default to `build=publisher-workflow,review=none`. All positions default to `verifier=local,appraisal=per-request`. Security-axis values below run strongest to weakest; verifier and appraisal values are alternative appraisal choices.

| Axis | Recognized values |
| --- | --- |
| code | `public-release`, `fixed-private`, `provider-controlled` |
| host | `current`, `outdated-firmware`, `stale` |
| gpu | `verified`, `gaps`, `unchecked` |
| egress | `none`, `metadata`, `any` |
| build | `reproduced-off-github`, `reproduced`, `publisher-workflow`, `signed` |
| review | `pinned`, `window`, `none` |
| verifier | `local`, `nras` |
| appraisal | `per-request`, `reuse` |

Only `build=publisher-workflow` and `review=none` are implemented. Other build/review values fail clearly as not yet supported, including `build=signed`. The Tinfoil router's authenticated release does not cover its hidden workers, so it gives no route-wide public admission. No current route is X1; bare `public-builds` therefore admits none.

## Forced values and categories

Code below `public-release` forces `egress=any` and prohibits `build` and `review`. `host=stale` forces `gpu=unchecked`. The name must match both categories: public-build names require public code; provider-trust names require private or provider-controlled code. Host-excluding names require `host=current,gpu=verified`; host-trusting names require at least one weaker value. Contradictions, unknown values, duplicate axes and malformed settings are rejected with an explanation. These rules leave 35 combinations of the four axes.

With `gpu=unchecked`, `verifier=nras` warns that it has no admission effect. NEAR, Chutes and Privatemode remain G3 and never contact NRAS. Opt-in NRAS for Tinfoil uses the [same GPU gates and added service trust](../security-model.md#admission-and-selection).

## Appraisal reuse

`appraisal=per-request`, the default, appraises a worker for every request. `appraisal=reuse` lets a Tinfoil public direct or billing-gateway request reuse the last accepted worker appraisal for the same route, model and complete policy, until five seconds before that appraisal's admission expiry. Expiry is the earliest of the check plus 60 seconds, the challenge plus five minutes and the witness timestamps plus seven days, so an appraisal serves for at most about 55 seconds. Reuse never extends expiry. Each request still opens its own transport with a fresh EHBP encapsulation to the appraised worker's HPKE key and a fresh cache salt, and sends once. Direct requests pin TLS to the appraised worker key; gateway requests use WebPKI TLS to the billing gateway, as without reuse. An appraisal becomes reusable only after its dispatch reads the response body to a clean end with every frame authenticated, and is unavailable to other requests while that dispatch is unfinished, so concurrent requests appraise afresh. A rejected or failed dispatch, a frame that fails authentication, a cancelled response, an aborted request and a disposed transport all drop it. EHBP has no authenticated end marker, so on the gateway route a clean end shows only that the frames received were authentic. Appraisals are kept in process memory only. Other providers and routes ignore the setting.

It skips selection and appraisal, about 2 seconds warm and 5 seconds cold for an eight-GPU worker ([measurements](../evidence/client/gpu-appraisal-latency.md)). In exchange:

- A reused request sends no challenge of its own. Its H and G levels describe evidence the client checked for an earlier request, up to about a minute old, not evidence fresh for this request.
- Changes inside that window go unseen: a newly revoked certificate, CPU collateral that falls out of date, a release the freshness witness stops endorsing, or a GPU leaving its protected mode while the worker keeps its keys. A worker that loses its keys fails the pinned TLS or HPKE binding and is dropped.
- An earlier appraisal authorizes later requests, so "a previous success cannot authorize a request" no longer holds within the window.
- Requests in the window go to the same worker and its keys, and Tinfoil and NVIDIA see fewer evidence and collateral requests.

Status shows each reused request's levels with an observation naming when the appraisal was checked. Code, release, key-custody and policy checks are not relaxed; they are not repeated either.

## Examples

Use the [provider guide's admission table](../providers.md) for supported routes. These settings express thresholds rather than permanent model ratings:

```text
public-builds,egress=metadata
public-builds,egress=metadata,appraisal=reuse
public-builds-trust-host,egress=metadata,host=outdated-firmware,gpu=verified
trust-provider-and-host,host=current
trust-provider-and-host,code=fixed-private
```

## Migration

The former default `public-builds` maps to `public-builds,egress=metadata`. Explicit bare `public-builds` now requests X1. Removed `sdk` returns a migration error directing users to `trust-provider-and-host`; adding `host=current` preserves outdated-instance rejection and excludes the Tinfoil router, whose hidden workers keep it at H3. Removed `approved` maps conceptually to `public-builds,review=pinned`, which is unsupported, not an accepted alias.

`PI_NEARAI_POLICY`, `PI_TINFOIL_POLICY`, `PI_NEARAI_ROUTE` and `PI_TINFOIL_ROUTE` return migration errors. Use `PI_TEE_POLICY` and automatic route selection. Policy changes abort active requests, affect only the named provider when issued as a command, and are not persisted.

Implementation: [parsePolicy()](../../packages/core/src/policy.ts), [assessRoute()/compareRoutes()](../../packages/core/src/security.ts). A qualifying weaker route may be selected only under the user's existing thresholds; verification failure never relaxes them.
