# Security model

A policy names who you trust and sets admission thresholds. Levels describe what the client verified for the current request. Unchecked properties receive the weakest possible level; the weakest component that holds plaintext determines each route-wide level. Routes without verified CPU evidence are outside this model.

Verified means hardware or manufacturer signatures the client checks, or the output of code verified at A1. Anything assembled by code below A1 counts as unverified. NEAR’s provider-assembled GPU coverage therefore remains G3; code below A1 cannot establish an egress limit.

Intel, AMD and NVIDIA as manufacturers, your machine, Pi and enabled local code are always trusted. Physical attacks on the serving host are outside the model.

## Policy setting

Set `PI_TEE_POLICY=<position>[,axis=value…]`. The shipped default is `public-builds,egress=metadata`. A bare name is strict for parties it excludes and loose for parties it trusts.

| Position | code | host | gpu | egress | Trust permitted |
| --- | --- | --- | --- | --- | --- |
| `public-builds` | public-release | current | verified | none | Neither provider nor host |
| `public-builds-trust-host` | public-release | stale | unchecked | none | Host |
| `trust-provider` | provider-controlled | current | verified | any | Provider |
| `trust-provider-and-host` | provider-controlled | stale | unchecked | any | Provider and host |

Public code still trusts its admitted publishers and build authorities. Public-build positions default to `build=publisher-workflow,review=none`. If the trusted host is the provider, or colludes with it, `public-builds-trust-host` effectively trusts both; status reports this caveat.

| Axis | Values, strongest to weakest | Verified meaning |
| --- | --- | --- |
| A: code | `public-release`, `fixed-private`, `provider-controlled` | A1 identifies publicly logged releases from pinned repositories and workflows, including the guest, configuration, runtime and key-custody chain. A2 pins all plaintext-capable private code but cannot inspect its behavior. A3 cannot establish which serving code runs or whether it changes. |
| H: host | `current`, `outdated-firmware`, `stale` | H1 binds CPU evidence to the client's fresh nonce and checks local firmware floors. H2 is fresh but below those floors, or cannot establish them. H3 checks evidence without a fresh nonce or local floors. |
| G: GPU | `verified`, `gaps`, `unchecked` | G1 authenticates every serving GPU, complete serving coverage, CPU-hashed evidence, local floors, and SPT or Blackwell MPT. G2 retains authenticity, freshness, confidential mode and complete coverage but permits documented gaps. G3 lacks complete serving evidence. |
| X: handling | `none`, `metadata`, `any` | X1 permits no egress or plaintext storage. X2 permits only fixed-destination authorization metadata, without body egress or storage. X3 cannot establish such limits. |
| B: build | `reproduced-off-github`, `reproduced`, `publisher-workflow`, `signed` | B1 reproduces off GitHub; B2 reproduces through an already trusted party on GitHub; B3 checks the named publisher workflow and hosted runner, including its endorsed engine artifacts; B4 checks a repository's signed release tag without checking workflow or runner. |
| S: review | `pinned`, `window`, `none` | S1 adds independent approval and pins; S2 requires a review interval in the public signing log; S3 imposes neither. |

Only B3 and S3 admission are implemented today. All other build/review settings, including `build=signed` (B4), fail clearly as not yet supported. The router can disclose B4 component evidence without implementing B4 public-code admission. No current route is A2 or X1. Weights count as code when executed; the admitted Tinfoil runtime rejects remote model code. Output correctness is outside this contract.

G2 gaps are unranked: Hopper PPCIe with unattested NVSwitches; nonce-only CPU–GPU association; or signed, unrevoked firmware below local floors. G1 and G2 require fresh CPU evidence. CPU-only plaintext components meet any G threshold. Firmware floors supplement signatures and revocation, without ranking all possible firmware security states. Still-valid collateral can lag a new revocation; see the [serving contract](tinfoil-public-profile.md).

## Forced values and categories

Code below `public-release` forces `egress=any` and prohibits `build` and `review`. `host=stale` forces `gpu=unchecked`. The name must match both categories: public-build names require public code; provider-trust names require private or provider-controlled code. Host-excluding names require `host=current,gpu=verified`; host-trusting names require at least one weaker value. Contradictions, unknown values, duplicate axes and malformed settings are rejected with an explanation. These rules leave 35 combinations of the four axes.

`verifier=local` is the default. `verifier=nras` authenticates NVIDIA's signed overall and per-device verdicts, then applies the same GPU mode, coverage, count, freshness, certificate/reference and firmware checks. It adds trust in NRAS's service keys, insiders and appraisal policy, discloses attestation timing and GPU identity to NVIDIA, and depends on service availability. With `gpu=unchecked`, it warns that NRAS has no effect. NEAR remains G3 and uses local GPU details only; its routes never contact NRAS.

## Routes and selection

The [Tinfoil billing gateway](tinfoil-gateway.md) is a fallback for DeepSeek V4.1 Flash and GLM-5.3 when no direct worker qualifies. It uses the same fresh worker appraisal and verified levels; direct is preferred because fewer parties receive credentials and metadata. WebPKI TLS ends at the unattested gateway, which sees the API key, model and headers. Bodies are sealed to the appraised worker, so that metadata disclosure is separate from the axes. A 412 fails without resending; a later request starts with fresh evidence.

A route must meet every threshold. Qualifying routes are compared by code, then host, then GPU, then egress. Public code can therefore outrank stronger hardware on provider-controlled code. Discovery and potential levels only filter candidates; they do not count as verified request levels. Unavailable or rejected candidates do not authorize prompt transmission.

| Route | Actual levels after successful checks | Tightest admitting policy |
| --- | --- | --- |
| Tinfoil direct, current worker | A1 H1 G1 X2 B3 S3 | `public-builds,egress=metadata` |
| Tinfoil billing gateway, current worker | A1 H1 G1 X2 B3 S3 | `public-builds,egress=metadata` |
| Tinfoil Gemma Genoa worker | A1 H2 G1 X2 B3 S3 | `public-builds-trust-host,egress=metadata,host=outdated-firmware,gpu=verified` |
| Tinfoil router | A3 H3 G3 X3 | `trust-provider-and-host` |
| NEAR direct GLM-5.3 Flash, current instance | A3 H1 G3 X3 | `trust-provider-and-host,host=current` |
| NEAR direct Qwen3.6 35B and Qwen3.8 27B, observed outdated instances | A3 H2 G3 X3 | `trust-provider-and-host,host=outdated-firmware` |
| NEAR gateway, observed outdated instances | A3 H2 G3 X3 | `trust-provider-and-host,host=outdated-firmware` |

NEAR direct discovers every matching tool-capable, attestation-declared catalog model in the endpoint registry, including GLM-5.3 Flash, Qwen3.6 35B A3B FP8 and Qwen3.8 27B today. Discovery only selects candidates; each request establishes levels and unreachable endpoints are skipped and reported in status. [Discovery and live validation](near-direct-discovery.md). NEAR ratings vary by instance: H1 requires Intel `UpToDate`, TDX SVN components at least `[3,1,2]`, and both verified TCB/QE collateral editions at least 20. Below-floor or unreadable values yield H2. Both NEAR routes take the weakest rating across every attestation the SDK verifies, including non-serving model instances and, for the gateway route, the CPU-only gateway. This can conservatively reject a request under `host=current` even if its serving instance meets the floors: shared model/response keys do not establish exclusive serving-instance custody. GPU coverage remains unknown even when every presented report authenticates; optional local details cannot raise G3 or gate admission.

Tinfoil Genoa H2 retains signed publisher firmware minima, manufacturer signatures/revocation, fresh nonce and endpoint binding, and production guest restrictions. **Tinfoil direct skips Intel `OutOfDate` TDX workers under every policy:** the pinned Go verifier rejects them during authentication. No dependency is patched to relax that restriction. A permissive threshold cannot make an unavailable verifier path usable.

Tinfoil's router receives prebuilt CPU evidence without a client nonce, does not check AMD revocation or local floors, and does not establish all worker/sidecar code or GPU protection. Its own signed tags supply B4 component evidence, but the complete route remains A3 and has no public-code build refinement. Hidden plaintext recipients and web search count toward its weakest levels. Under `trust-provider-and-host`, the pinned SDK retains its single EHBP key-configuration mismatch recovery: re-attest and resend the same guarded request once. A second mismatch or another request error fails; Pi does not add retries.

## Status and commitments

`/tinfoil status` and `/nearai status` show the position, thresholds, permitted trust, actual route levels, every computed gap and observed detail, and why each candidate qualified, failed or was selected. Before a request they say that route levels are not established. Reports contain no prompts, completions, credentials or quote bodies.

For a NEAR H2/G3 instance, status names NEAR's ability to read plaintext and change serving code, host trust from outdated firmware and incomplete GPU coverage, X3 handling uncertainty, and observed details such as Intel `OutOfDate`, Hopper PPCIe, shared-nonce association or an R570 driver branch without a listed May 2026 fix. Manufacturer verification does not establish exclusive serving-instance custody.

C (commitments) is displayed separately from admission: NEAR's ToS/DPA do not promise contractual no-retention; inspected Responses source stores transcripts without a TTL, while the inspected Chat Completions path does not persist transcript content (deployment unverified); NEAR promises no training and lists ISO 27001, without a public SOC 2 report; the sub-processor list does not consistently cover Chutes-backed models. Tinfoil commitments have not been reviewed. These observations neither change a route level nor prove deployed handling behavior. [NEAR assessment](nearai-status.md).

## Migration

The old default `public-builds` maps to `public-builds,egress=metadata`. Explicit bare `public-builds` now requests X1, which no route supplies. Removed `sdk` returns a migration error directing users to `trust-provider-and-host`; adding `host=current` preserves outdated-instance rejection and also excludes the stale Tinfoil router. Removed `approved` maps conceptually to `public-builds,review=pinned`, which is not yet supported.

`PI_NEARAI_POLICY`, `PI_TINFOIL_POLICY`, `PI_NEARAI_ROUTE` and `PI_TINFOIL_ROUTE` are removed and return migration errors. Both providers read `PI_TEE_POLICY` and select routes automatically. Session policy commands accept the same syntax, change only the named provider, abort its active requests and do not persist changes. A qualifying weaker route may be selected only if the user's existing thresholds admit it; a verification failure never relaxes those thresholds.
