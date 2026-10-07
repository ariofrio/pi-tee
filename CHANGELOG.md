# Changelog

## Unreleased

- Require the Intel candidate's signed Hopper report to declare SPT mode after local NVIDIA verification. Correct for the inspected C++ mode enum/JSON limitations using NVIDIA's Python field interpretation, reject ambiguous records, and preserve terminal mode diagnostics without retries. Add evidence-CLI and native-provider regressions; public-build inference qualification remains separate.

- Authenticate Tinfoil guest builds through the exact public CVM release workflow, source commit and signed manifest/kernel/initrd/disk subjects. Derive guest versions dynamically, check downloaded kernel/initrd bytes and the verity/config-bound boot command, and recompute RTMR2 in the live public-build probe. Add offline real-signature substitution tests; inference qualification remains separate.

- Select `public-builds` as the default policy target: authenticated updates from named public release/build authorities, without maintained deployment pins. Keep inference blocked until a complete serving profile qualifies; preserve explicit SDK routes and optional Approved semantics. Add a separate automatic Tinfoil public-release/CPU verifier and live artifact/source probe, with exact workflow identities, signed freshness, local hardware floors and real-evidence rejection tests. Fresh locked install, build/types, 40 provider tests, compiled/isolated package login checks, Go tests/vet and the live public-artifact probe pass; no inference is sent by the probe.

- Trace the Intel candidate's boot artifacts to the fixed configuration/root hash, recompute RTMR1/RTMR2, and add an offline RTMR2/artifact check with real-artifact mutation validation. Document checked runtime source paths and the remaining workload qualification work.

- Add an opt-in Intel direct Gemma candidate with fresh locally pinned TDX policy, local NVIDIA appraisal of CPU-bound evidence, helper/library/image hash checks, exact TLS/HPKE binding and encrypted vLLM cache salt. Its full actual Pi suite and separate live streaming cancellation pass. Record the closed hardware/local-artifact inventory, combined real GPU negatives and remaining independent workload/runtime gates; production Approved defaults are unchanged.

- Add an experimental native GLM direct route for NEAR SDK policy. Require fresh UpToDate CPU evidence, GPU evidence, quote-bound SPKI on one TLS socket, OHTTP and model-response signatures. Reject reconnect/resend, limit the route to GLM and dispose owned transports after terminal results. Add real TLS and native-provider cleanup regressions.

- Add locked, offline CPU qualification tooling with local AMD/Intel workload and security pins. Fresh Intel appraisal and real-evidence binding negatives pass without provider reference/freshness collateral; the sampled AMD worker fails manufacturer-based firmware floors. Probe reachable alternatives and record separate Intel GPU appraisal; extension defaults and Approved gates remain unchanged.

- Add an explicit pinned Gemma direct-worker route for Tinfoil SDK policy. Verify the exact artifact/tag/measurement and the attested TLS socket before transmitting credentials or EHBP ciphertext; send once and fail on rotation. The full actual Pi suite passed, including RPC cancellation; a separate streaming cancellation run passed after a live text delta without a test delay. Correct the harness's response notification path and document the response-consumption test boundary.

- Add adapter-owned direct endpoint selection, route model restrictions, and TLS SPKI checks on the exact socket before HTTP transmission. Native-provider routing and real-socket rejection tests cover caller overrides, stale selections, and zero credential/body sends on a wrong TLS key.

- Add evidence-only and opt-in synthetic direct-worker research probes. NEAR GLM passed strict same-TLS attestation and signed inference; Qwen remained `OutOfDate`. A Tinfoil Gemma SEV worker passed SDK verification and direct EHBP inference. Document the exact deployment artifact and remaining approval gates; registered provider routes and defaults are unchanged.

- Accept Pi's text reasoning replay during tool-result follow-up; add failing-then-passing positive and structured-reasoning rejection tests. Record successful live Tinfoil completion, tools and reasoning with a corrected credential, while keeping cancellation and a complete live-suite pass unvalidated.

- Preserve reusable guarded request bodies for Tinfoil SDK key-rotation recovery; add a failing-then-passing provider regression without adding Pi retries or independent approval claims.
- Add opt-in, billable real Pi CLI/RPC validation with isolated native login, synthetic completion/tools/reasoning/cancellation checks and credential-safe diagnostics. Record current NEAR TCB-policy and Tinfoil credential failures without weakening verification policy.
- Adopt unscoped `pi-nearai`, `pi-tinfoil` and `pi-tee-core` package names; publish the WIP source and assessment under `ariofrio/pi-tee`.

- Hide NEAR models without declared serving-attestation support by default; add independent visibility settings and labeled show-all discovery without relaxing inference verification.
- Add separately installable NEAR AI and Tinfoil Pi provider extensions with shared policy and transport enforcement.
- Add native API-key login, public model catalogs, native stored refresh, provider-specific policy/report commands, and safe default blocking.
- Add SDK-policy transports; hold NEAR response bytes until model signature verification completes.
- Add payload/header/model guards, bounded buffering, cancellation and terminal retry suppression.
- Keep independently approved production profiles and session-wide protection gated; document their remaining requirements.

Written by Codex.
