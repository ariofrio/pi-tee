# Changelog

## Unreleased

- Harden the pinned TLS client: malformed response headers fail the request instead of crashing Node, a stalled reader pauses the socket, close-delimited bodies are rejected, and the negotiated TLS version is checked because Bun ignores `minVersion`.

- Extend the Tinfoil public-build profile to DeepSeek V4.1 Flash and GLM-5.3, alongside Gemma 4 31B. Accept AMD SEV-SNP evidence (Genoa/Turin roots, AMD CRL, publisher TCB floors, non-debug non-migratable VMPL0 guests) as well as Intel TDX. Appraise every CPU-bound GPU: one claim per device, one supported hardware model, distinct devices, per-model firmware floors, and SPT for one GPU or Blackwell MPT for several. Replace the Gemma-only runtime profile with `tinfoil-vllm-v1`, and discover and freshly appraise workers on each dispatch instead of pinning one host. Tinfoil's remaining models are reachable only through a router that does not enforce the policy and stay excluded. Production admission stays closed pending review.

- Raise weaker SEV-SNP firmware floors from the platform publisher to local backstops, matching the existing TDX floors. Current publisher floors already equal them.

- Recompute the SEV-SNP launch digest from the authenticated kernel, initrd and command line with a pinned, attested OVMF, matching the existing TDX register recomputation.

- Retry transient 502/503/504 responses while fetching public artifacts; every byte is still authenticated by digest or signature.

- Replace the Docker-hosted NVIDIA verifier and native Go helpers with WebAssembly modules shipped in `pi-tinfoil`: NVIDIA's verifier with the reference-signer patch (Emscripten) and the public-build CPU/release verifier (WASI). Both are hash-checked before compilation and run in terminable worker threads; the CPU verifier has no file system or network, and the NVIDIA verifier reaches only NVIDIA's reference and OCSP services. No setup step remains. Remove the frozen `direct-intel` route, `pi-tinfoil-setup`, the native NVIDIA candidate and the Go TLS helper. The experimental `sdk`-policy `direct-public` route runs the full appraisal; production `public-builds` admission stays closed pending review.

- Send pinned-TLS requests as one HTTP/1.1 exchange on the verified `node:tls` socket instead of through `https.Agent`, which Bun cannot bind to an existing socket. The actual Pi suite, including live-delta cancellation, passes under Node and the Bun-compiled Pi 1.0.4 binary.

- Map NEAR models' Pi `maxTokens` to their context length. NEAR advertises `max_output_length` 8192 for several models but does not enforce it, and Pi already clamps requests to the remaining context.

- Pause Tinfoil public-build admission until the native GPU verifier replaces the pinned Linux verifier and passes review. Admission and the Intel research route fail before collecting evidence; the default policy exposes no models.

- Verify native-candidate GPU reference-manifest signatures with the certificate-chain leaf key and require whole-document references. The patch is applied to a hash-checked copy of the pinned NVIDIA source.

- Restrict native-verifier builds to a toolchain environment, package a hash-checked OpenSSL configuration and strip runtime overrides. Add reference/OCSP signature negatives with authentic delivery controls to the six-target workflow. Remove source paths from application compilation and fix a Windows logging-macro collision. The native verifier remains a candidate; production admission is unchanged.

- Keep the authenticated native-verifier Cargo lock in LF form on Windows, preserving its exact pinned hash across checkout settings.

- Add a Docker-free native NVIDIA verifier build candidate with locked SDK, Rust and dependency inputs, disabled local collectors and six-target desktop execution checks. Test real GPU nonce, report/mode signature and certificate-signature rejection. Production verification and admission remain unchanged; packaging and full qualification are unfinished.

- Retry temporary helper-file locks during cleanup and handle persistent removal failures without terminating Pi. Only the executable snapshot can remain; no request data is written there.

- Strengthen the isolated expiry regression with an independent loopback IPC observer. Catch a request write before a misplaced expiry check, even when the parent subsequently returns the expected error. Production transport is unchanged.

- Limit native TLS connection setup to ten seconds without cutting off admitted response streams. Bind TLS fixtures to loopback and test the parent-side expiry check independently of the Go helper's own check.

- Add public Tinfoil worker discovery and an evidence-only probe covering every advertised candidate for the seven current chat workloads. Fix delivery services, compare the expected publisher repository, bound results and reject arbitrary hosts/releases; ignore claimed keys and measurements. Support worker hostname aliases independently of catalog IDs. Production routing and admission are unchanged.

- Separate NEAR model TEE declarations from SDK protocol support. Declared Chutes models are no longer labeled non-TEE; discovery reports their unavailable transport, the default picker hides them, and show-all labels them accurately. SDK dispatch fails before setup; public profiles remain independent of SDK support. Preserve the distinction in offline snapshots.

- Recheck public admission expiry after TLS setup before sending credentials or ciphertext, in both the native and portable transports. Pass the verified deadline from Tinfoil sessions; check it again inside the helper before its sole HTTP write. Add slow-handshake and post-readiness expiry negatives. Accepted response streams may continue past the dispatch deadline.

- Add an optional owned Go TLS transport for portable Node/Bun integration. Authenticate the socket before passing credentials/body to the helper; snapshot hash-checked artifacts, stream bounded frames and close processes/sockets on cancellation. Add real socket, dropped-response/no-replay and Node/Bun tests plus a candidate Pi harness. Production routing and GPU-verifier dependencies are unchanged.

- Allow separate public-build profiles for different models in one provider. Bind each admission, authority digest and expected endpoint to its canonical model; reject ambiguous profile ownership and inconsistent session endpoints before transmission. Each profile declares its own trust assumptions. Adapters sharing a URL must isolate workloads through their attested connections. Existing production coverage is unchanged.

- Clarify NEAR gateway coverage: 20 fresh evidence-only checks distinguished two measured instance IDs, both `OutOfDate`. Record the evidence and avoid extrapolating to the entire fleet; verification policy is unchanged.

- Enable the reviewed Tinfoil Gemma public-build profile on the documented macOS ARM64/OrbStack setup. Default auto routing now selects the owned Intel worker under public policy; router users must explicitly choose SDK policy. Add production activation/no-fallback regressions and actual compiled-extension public-policy validation. NEAR public builds, independently Approved workloads and whole-session protection remain unavailable.

- Select Tinfoil routes automatically by policy: owned worker admission for public builds (still gated for final wiring review), SDK router for explicit SDK policy. Report public-profile assumptions independently of SDK route assumptions; preserve explicit router rejection under public policy. State the tested OrbStack/containerd builder scope and make the setup negative robust to Node deprecation warnings.

- Package locked CPU-verifier source and add `pi-tinfoil-setup` for macOS ARM64. Authenticate NVIDIA/Ubuntu archives, reproduce the pinned GPU image without RUN network access, check its OCI tar hash before loading, and reject substituted cached dependencies. Two clean image builds are byte-identical and the image passes real local NVIDIA appraisal. Clarify declared trust closure, admission records and unsupported schema/platform limits.

- Add owned public-build sessions with canonical model/endpoint, authority-policy and artifact digests, fresh admission/expiry checks, policy-change cancellation and no SDK fallback. Bind the real Intel public-build chain to that contract; keep production admission disabled pending repeatable setup and final review. Add native mismatch/expiry negatives, including expiry during a Pi payload hook, and a synthetic actual-Pi candidate harness.

- Document the closed Tinfoil public-build authority/process set, plaintext/key custody, operator inputs and publisher/manufacturer channel/reset contracts.

- Reject remote or unapproved Docker verification endpoints before collecting evidence; bind NVIDIA appraisal and cleanup to the checked local Docker Desktop or OrbStack Unix socket. This assumes the local OS and socket service are trusted.

- Cache immutable public-build artifacts and deterministic helper results within the Pi process, with bounded memory and fresh CPU/GPU/freshness appraisal on every request. Execute private copies of verified public-build and NVIDIA helpers, and clean them after appraisal. Add warm-cache, nonce and helper-replacement regressions through the real verifier/delivery boundary.

- Allow newer NVIDIA driver/VBIOS versions in `direct-public` when they satisfy explicit local floors and all existing manufacturer signature, reference, revocation, nonce and SPT checks. Preserve exact versions for the frozen Intel candidate. Evidence-CLI tests check version compatibility without claiming authentication of synthetic reports.

- Bind downloaded deployment/runtime/container inputs to the CPU-accepted signed predicate and statement digest. Recompute boot registers against the quote's authenticated expectations, require unambiguous collateral selection, apply security floors to an owned policy copy, enforce public platform/freshness workflow certificates, and reject JSON parser ambiguities. Add real-verifier Node delivery-substitution tests and a public inspection test of weak/strong TDX floors. Production admission remains gated.

- Recompute RTMR1/RTMR2 in the shared dynamic build chain using a bounded, attributed TypeScript port of the release measurement algorithm. Reject unsupported PE layouts; test real release registers, code/command substitutions and malformed layouts without claiming build authentication. The full actual Pi suite passes with the new boot gate; the package includes the component's Apache license.

- Add the SDK-policy `direct-public` Intel candidate: authenticate fresh dynamic release/guest/OCI/source/runtime evidence before local NVIDIA appraisal and send-once encrypted inference. Share the artifact chain with the evidence probe, reject untrusted local helpers through native Pi, and retain the default production gate. All 44 provider tests, package loader checks, the full actual Pi suite and separate live-delta cancellation pass.

- Enforce a Gemma runtime configuration contract after authenticating the named public release: bind VM shape, guest/config boot hashes, dynamic image/model roots, literal environment, engine flags, routes and health checks. Reject host access, unknown environment, remote code, logging and ambiguous YAML/arguments. Connect it to the evidence-only live chain; standalone and combined results still deny inference qualification.

- Test signed GPU-mode coverage at the real NVIDIA verifier boundary: changing only SPT to MPT returns signature-error result `508`, alongside forged-signature and wrong-nonce negatives. Require SPT in the Intel research probe as well as the native candidate; the evidence-only run passes with zero inference.

- Validate automatic guest-build updates with real signed CVM `v0.11.0` and `v0.14.13` artifacts under the unchanged verifier/workflow/root policy. Record both offline fixtures; this proves the guest-build stage, not a second qualified inference deployment.

- Follow the authenticated Tinfoil release into its dynamic OCI image/config/provenance digests and public build-source/Dockerfile checks. Treat embedded BuildKit metadata as publisher-endorsed claims, explicitly without independent builder-signature verification. Add offline real-signature/artifact substitutions, including rehashed metadata; the combined live evidence probe passes without inference.

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
