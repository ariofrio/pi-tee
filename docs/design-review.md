# Review: NEAR AI and Tinfoil providers for Pi

Reviewed: [design.md](design.md) (2026-10-06). Reviewer: Opus 5.5, independent child thread. This is a design review against the pinned source snapshots and official docs. It is not an audit or certification. No authenticated inference, live attestation, or rebuild was performed.

## Verdict

The security direction is sound. The design does not overclaim: Approved workloads fails closed, the NEAR same-TLS-connection route is framed as a candidate, and SDK policy is kept separate from independent approval. Most factual claims match the source (see [Claims checked](#claims-checked-and-found-accurate)).

**Ready to implement after the Medium fixes below:**

- `/login` and catalog for both providers
- SDK-policy providers
- shared policy, evidence, and session contracts
- negative tests

**Not ready, and should stay gated:**

- Production Approved workloads for either provider.
- NEAR: the source shows server-side authorities that no client check can remove: shared keys, KMS-controlled key release, compose-manager mutation, and an unpinned runtime download of weights.
- Tinfoil: the direct-worker path is the more promising first Approved target. Its blockers are worker reachability, the CPU-platform verifier, pinned hardware measurements, and GPU policy. Key custody appears to be per-boot.

The design needs three corrections before implementation:

- Tinfoil `SecureClient.fetch` re-sends requests after re-attesting, with no point to apply local approval first (H1).
- The SDK-policy reports must state what the SDKs do **not** check (H2).
- Several concrete entities found in source are missing from the trust closure (H3).

## Findings

Severity: **High** = a wrong security claim or an unenforceable guarantee if implemented as written. **Medium** = a feasibility or completeness gap that needs a design change. **Low** = clarity or accuracy.

### H1. Tinfoil `SecureClient.fetch` re-attests and re-sends with no pre-send approval point (confirmed)

**Evidence.**

- [`SecureClient.fetch`](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts#L370-L385) catches `KeyConfigMismatchError`, then calls `reset()` and `ready()`. It then re-sends the same request to whatever release the SDK accepts next.
- [`initSecureClient`](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts) takes its bundle from ATC. The no-ATC [assembler](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/verifier/src/bundle.ts#L39-L43) reads `releases/latest` through `github-proxy.tinfoil.sh`.
- The [Sigstore policy](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/verifier/src/sigstore.ts#L86-L91) requires only the issuer, the repository, and `refs/tags/*`.
- `createSecureFetch` is not exported ([index.ts](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/index.ts)). `Verifier`, `assembleAttestationBundle`, `fetchAttestationBundle`, and the `ehbp` package are public.

**Impact.**

- Lifecycle step 4 says SDK re-attestation "must invoke the same approval gate." That cannot be done through `SecureClient.fetch`.
- The provider choice for Tinfoil SDK policy ("checks after every SDK verification/key rotation") can only run after the body has been sent. That is acceptable only because SDK policy accepts the SDK's rules by definition.
- SDK policy also accepts any historical tagged release that ATC or the proxy chooses to present. There is no rollback floor. The design's description ("a configured repository's tagged release") is accurate, but it does not state this consequence.

**Fix.**

- Approved workloads must not use `SecureClient`. VerifiedTransport should:
  1. call `Verifier.verifyBundle`;
  2. apply the local policy, with the exact digest pinned;
  3. build the `ehbp` transport directly against the approved HPKE key;
  4. handle `KeyConfigMismatchError` itself by re-appraising before any re-send.
- Label SDK-policy reporting as post-hoc.
- Add "accepts any signed tagged release (no rollback floor)" to the SDK-policy disclosure.
- Add this adversarial test: the server rotates keys during a request, and the re-attested release is SDK-valid but unapproved. Expected result: no second send.

### H2. SDK-policy disclosures must list what the SDKs do not check (confirmed)

The design rightly calls an SDK success "not independent approval." It does not, however, specify the "not established" properties that each SDK-policy report must show. Without that list, an SDK-policy footer will read as "hardware and software verified."

**NEAR guest OS and firmware.** The SDK never appraises MRTD or RTMR0–2.

- The [Intel adapter](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/utils/intel.ts#L105-L112) returns only `tcbStatus`, `advisoryIds`, `debugEnabled`, `reportData`, `mrConfigId`, and `rtMr3`.
- `os-image-hash` is read from the RTMR3 [event log](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/core/event-log.ts#L68). That log is extended by the booted guest itself, so the value is self-asserted unless MRTD and RTMR0–2 are checked.
- Under SDK policy, OS and firmware integrity is therefore delegated entirely to whatever KMS or contract gates key release. That is a deployment fact the client does not see.
- The design states the MRTD/RTMR0–2 requirement for Approved workloads. It should also state this gap for SDK policy.

**NEAR GPU.**

- [`nvidiaNrasVerifier`](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/utils/nvidia.ts#L55-L58) accepts NRAS's overall verdict (`x-nvidia-overall-att-result`, [L113](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/utils/nvidia.ts#L113)). Per-device claims are not consumed. "Approved firmware/reference measurements" therefore cannot be enforced through this path; NVIDIA's remote appraisal policy decides.
- GPU evidence defaults to `if-present`.
- GPU checking is ["independent of the model's CPU quote"](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/core/attestation-model.ts#L102-L114).

**Tinfoil JS verifier.**

- The [cert-chain check](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/verifier/src/sev/cert-chain.ts#L42-L44) supports only Genoa.
- The pinned verifier has no VCEK/ASK CRL or revocation check; a grep for `crl` and `revocation` found nothing.
- TCB floors are hard-coded in [`defaultValidationOptions`](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/verifier/src/sev/validation.ts#L52-L92).
- The SDK attests the **router**, not the model worker. The design already notes this.

**Fix.**

- Make `SDK policy` reports a fixed table of established and not-established properties, populated from the facts above.
- Approved workloads must perform local appraisal of each item: raw-quote MRTD/RTMR0–2 against approved image builds, per-device GPU claims or local RIM comparison, AMD CRL checks, and an explicit platform-generation allowlist.

### H3. Trust closure is missing concrete entities found in source (confirmed unless marked)

The design specifies the mechanism and defers the inventory, which is reasonable. The following entities are concrete enough to belong in the design now, as manifest rows or release gates.

**Tinfoil**

- **`tinfoilsh/hardware-measurements` latest-release authority.**
  - For TDX backends, the router checks MRTD/RTMR0 against [`LatestHardwareMeasurements`](https://github.com/tinfoilsh/tinfoil-go/blob/05e817920780362d6c79b0035902d51bd608918b/verifier/sigstore/sigstore.go#L365-L374), called from [`addEnclave`](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/manager/manager.go#L308-L313).
  - The Go client [uses the same latest-release default](https://github.com/tinfoilsh/tinfoil-go/blob/05e817920780362d6c79b0035902d51bd608918b/verifier/client/client.go#L263-L276) unless `hardwareMeasurements` is supplied.
  - The design recommends the Go verifier/CLI for TDX, so that path inherits this second provider release authority unless the helper pins the entries.
  - The design's router finding names only the backend-release authority.
- **Router enclave composition** ([tinfoil-config.yml](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/tinfoil-config.yml#L10-L41)):
  - A `safeguards` sidecar receives plaintext transcripts and reports to the control plane.
  - The router network is [`egress: open`](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/tinfoil-config.yml#L86-L88).
  - `UPDATE_CONFIG_URL` points at the operator API.
  - Classification is skipped for API keys ([`Observe`](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/safeguards/capture.go#L44-L50)). The recipient set is therefore decided at runtime by credential type, and a policy that relies on it must approve that router code path.
  - This applies to the router-change option. The direct-worker option avoids it.
- **Delivery actors that choose which signed release is presented:** ATC (`atc.tinfoil.sh`), `github-proxy.tinfoil.sh`, and `kds-proxy.tinfoil.sh`. They are delivery-only only if the client pins digests; see H1 on rollback.
- **GPU appraisal inside the guest** ([gpuattest.go](https://github.com/tinfoilsh/cvmimage/blob/46c2430be746e1ad2d783046252d825a77c3f2b1/tinfoil/cmd/boot/gpuattest.go#L109)):
  - The guest runs `nvattest --verifier local` at boot. To verify: its RIM and OCSP dependencies and its bundled policy.
  - Blackwell multi-GPU shapes require no in-guest NVSwitch evidence ([`RequiresNVSwitchEvidence`](https://github.com/tinfoilsh/cvmimage/blob/46c2430be746e1ad2d783046252d825a77c3f2b1/tinfoil/internal/attestation/gpu.go#L54-L73)). The policy must state the topology and link-encryption assumption that replaces it.

**NEAR** ([compose recipe](https://github.com/nearai/cvm-compose-files/blob/cda2032fa8f8638639d858703b6de4d76c2118e8/prod/dsv4-qwen36-gemma4.yaml), byte-identical to the local copy)

- **Runtime weight download with unpinned tooling.**
  - [L264](https://github.com/nearai/cvm-compose-files/blob/cda2032fa8f8638639d858703b6de4d76c2118e8/prod/dsv4-qwen36-gemma4.yaml#L264) runs `uvx --from 'huggingface_hub[hf_xet]' hf download … --revision …` at container start.
  - That resolves unpinned packages from PyPI inside the CVM, and writes weights from Hugging Face into a shared volume that vLLM loads.
  - PyPI, those package maintainers, and Hugging Face delivery are therefore in the serving-integrity closure, unless measured code verifies the weight hashes.
  - Contrast Tinfoil, whose measured config pins weights by `mpk` hash ([gemma manifest](https://github.com/tinfoilsh/confidential-gemma4-31b/blob/dc843335b9321cba44672c3035d1fe00a610afda/tinfoil-config.yml)).
- **One certificate for all models and instances.**
  - [L1460–L1466](https://github.com/nearai/cvm-compose-files/blob/cda2032fa8f8638639d858703b6de4d76c2118e8/prod/dsv4-qwen36-gemma4.yaml#L1460-L1466) uses a single `completions.near.ai` key for every model server block, plus `-i<N>` "rotation-SNI" names for instance discovery.
  - Together with [cvm-ingress](https://github.com/nearai/cvm-ingress/blob/c785c6ed8d4ec0bb0ec4bcb45ef7afe3de48b24e/entrypoint.sh#L19), which derives the S3 archive key from the app's KMS key, this makes fleet-wide sharing the working assumption.
  - The design's hedge ("do not prove that every … instance shares one key") is correct. The release gate should presume sharing until disproven.
- **One secret for signing, E2EE, and OHTTP.** The OHTTP gateway is built from the ed25519 signing secret ([inference-proxy main.rs L90, L106](https://github.com/nearai/inference-proxy/blob/993238cf39d53a0c547bb8012d39dfe3d958ae77/src/main.rs#L90-L106)). OHTTP is absent from the design; it inherits the shared-key ambiguity.
- **Privileged containers with key-derivation access.** The proxy is `privileged: true` and mounts `dstack.sock` ([L33–L41](https://github.com/nearai/cvm-compose-files/blob/cda2032fa8f8638639d858703b6de4d76c2118e8/prod/dsv4-qwen36-gemma4.yaml#L33-L41)). Every container in the CVM sits in the plaintext and key closure, including the OTel collector, DCGM exporter, registrar, and downloader.
- **compose-manager authorities.** Per the [README](https://github.com/nearai/compose-manager/blob/aa9de34419c753c432259ecbcc717b6e2a7357c6/README.md), it deploys tags of a GitHub repository with an age check and accepts `env` overrides from bearer-token holders. Name both as authorities: write access to `cvm-compose-files`, and the holders of compose-manager tokens (the dashboard).
- **Uncertain deployment fact:** whether production NEAR AI Cloud uses `near-kms` or another dstack KMS. The design already conditions on this.

**Fix.** Add these entities as manifest rows. Add release gates for:

- pinned `hardware-measurements` entries
- per-architecture GPU topology rules
- measured verification of weight hashes
- the complete container list with privileges
- the OHTTP key

### M1. Pi cannot stop a protected transcript from being replayed to another provider (confirmed)

**Evidence.**

- Pi supports mid-session model switching and cross-provider handoff.
- [Virtual models](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/core/virtual-models.ts#L1-L10) route each request, including the [`retry`](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/core/virtual-models.ts#L43-L48) reason, to any physical model.
- Extensions cannot veto a request:
  - Exceptions in `before_provider_request` handlers are caught and logged ([`emitBeforeProviderRequest`](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/core/extensions/runner.ts#L1361-L1389)).
  - `model_select` is notification-only.

**Impact.** "Automatically switching to another provider is prohibited by the policy" has no mechanism. A user switch, or a virtual-model fallback, sends every TEE-protected message to an unapproved provider.

**Fix.**

- Mark protected sessions.
- In a `context`/`context_with_system` handler, strip or refuse protected content when the active physical model is not policy-approved.
- Revert the selection with `pi.setModel` and warn the user.
- Reject virtual-model routing unless the router extension is in the local trust inventory.
- State that this is a local-policy guarantee only.
- An upstream "veto provider request" hook is an optional Pi contribution, not a prerequisite.
- Add tests for a user switch, `--models` cycling, and virtual-model fallback.

### M2. Pi's two retry layers will automatically re-send after gate failures (confirmed)

**Evidence.**

- The OpenAI SDK wraps any error thrown from `fetch` as a connection error with an undefined status.
  - Pi's [`isRetryableProviderError`](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/ai/src/utils/provider-retry.ts#L23-L35) retries any undefined status.
- The session-level auto-retry ([agent-session.ts L1863](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/core/agent-session.ts#L1863)) restarts the whole turn.
  - It triggers on any message matching `connection.?error`, `terminated`, `timeout`, or `ended without` ([retry.ts](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/ai/src/utils/retry.ts#L30-L100)).

**Impact.** Step 6 ("Do not automatically retry a possibly executed request") is not enforceable as written.

- Truncated EHBP streams and failed NEAR signature checks will be re-sent.
- Policy rejections will also loop until the retry budget runs out.
- Confidentiality still holds if the gate is correct. Billing, and requests the server has already executed, are affected.

**Fix.**

- Force `maxRetries: 0` in the provider wrapper.
- Surface gate and integrity failures as terminal, non-retryable errors: either emit a stream `error` from a custom `streamSimple` wrapper, or normalize the text in a guarded `message_end` handler.
- Add tests for both retry layers.

### M3. Runtime and transport feasibility gaps in Pi (partly confirmed, partly to verify)

**The runtime check must not be "Node 24".**

- Pi requires Node ≥22.19 ([package.json](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/package.json#L105-L107)).
- Pi also ships **Bun-compiled binaries** ([build-binaries.sh](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/scripts/build-binaries.sh#L133-L135)), and extensions run in-process.
- The NEAR route depends on Node TLS socket APIs: [`getPeerCertificate`](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/node/attestation-client.ts#L247), pinned socket reuse, and possibly `exportKeyingMaterial`.
- **To verify:** how those APIs behave under the Bun binary.
- **Fix:** gate on the runtime and on probing each required capability, and fail closed with a clear message. Alternatively, run the NEAR transport in a pinned Node helper, which the design already allows.

**Buffer in the body stream, not inside `fetch`.**

- If `fetch` waits for the whole signed response before resolving, the OpenAI SDK's `timeout` becomes time-to-completion instead of time-to-headers. A timeout is then retried (M2).
- Return a `Response` as soon as headers arrive. Its body stream buffers internally, verifies, and only then releases bytes.
- **To verify:** the exact `fetchWithTimeout` behavior in the pinned `openai` dependency.

**Headers.**

- Caller and extension headers override provider defaults ([openai-completions.ts L788](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/ai/src/api/openai-completions.ts#L788)).
- Session-affinity IDs can be added, and EHBP and NEAR E2EE do not encrypt headers.
- VerifiedTransport should allowlist headers.

### M4. Use Pi's native catalog refresh instead of custom timers and snapshots (confirmed)

**Evidence.**

- Pi already calls provider refresh:
  - at interactive startup ([L1141–L1148](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/modes/interactive/interactive-mode.ts#L1141-L1148));
  - after `/login` ([L6118](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/modes/interactive/interactive-mode.ts#L6118));
  - when the model selector opens;
  - in RPC mode.
- [`createProvider({ fetchModels })`](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/ai/src/models.ts#L1007-L1011) restores and persists a snapshot that Pi manages, through `context.stored` and `context.publish`.
- Only `pi update --models` skips extensions ([package-manager-cli.ts L605–L614](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/package-manager-cli.ts#L605-L614)).
- The existing Tinfoil extension's comment that `fetchModels` "would be dead code" ([L418](https://github.com/tinfoilsh/pi-provider/blob/187fcfc1e04abfc5a44d16bf1523a8a88f38d3ed/tinfoil.ts#L418)) is true only for that command.
- Print and JSON modes do not refresh.

**Fix.**

- Implement `fetchModels` with a 4-hour freshness check against `context.stored.checkedAt`, and keep `/tee models refresh`.
- Document that print and JSON modes use the stored snapshot.
- `models.json` overrides compose above native providers ([custom-provider.md](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/docs/custom-provider.md)). The transport must ignore `baseUrl`, `headers`, and `compat` that come from overrides.

### M5. Re-prioritize Approved workloads by provider (confirmed facts, uncertain deployment)

**Tinfoil evidence:**

- Workload keys are [per-boot](https://github.com/tinfoilsh/cvmimage/blob/46c2430be746e1ad2d783046252d825a77c3f2b1/tinfoil/internal/attestedkeys/store.go#L1-L2), and the TLS key is written to ramdisk.
- Weights are measured through the `mpk` hash.
- The inspected shim's containers endpoint is read-only.
- Workers require authentication for `/v1/chat/completions` (`shim.authenticated: true`).

**NEAR evidence:** the blockers are all server-side (H3).

**Fix.**

- Make "Tinfoil direct SEV worker" the first Approved target.
- For NEAR, state that the client proof of concept validates the transport and the negative tests only. It cannot produce an approvable profile without NEAR server changes.
- Add about one week for a signed, cross-platform Go TDX helper (darwin/linux × arm64/x64) if TDX workers are needed.
- The other estimates are plausible for one experienced engineer.

### M6. A smaller NEAR server contract the client can check: attested TLS-exporter binding (recommendation)

The design's server-side fix — an ephemeral, enclave-local transport key — is correct but heavy.

**Alternative.** The TLS terminator inside the attested CVM puts an RFC 9266 `tls-exporter` value for the client's own session into `report_data`, in a field separate from the nonce. The client compares it with `TLSSocket.exportKeyingMaterial`.

**What this closes.** The evidence-relay attack:

1. A holder of the shared certificate terminates the client's TLS connection.
2. It fetches an honest instance's fresh quote with the client's nonce, for example over the plain-HTTP ports 8000–8003 that nginx exposes ([L1436](https://github.com/nearai/cvm-compose-files/blob/cda2032fa8f8638639d858703b6de4d76c2118e8/prod/dsv4-qwen36-gemma4.yaml#L1436)).
3. It returns that quote on the client's connection.

With exporter binding, the relayed quote carries the honest instance's own session exporter, which does not match the client's, so the client rejects it. This works even when the certificate keys are shared.

**What it does not fix.** compose-manager mutation and the KMS recipient set.

**Requirement.** nginx would need to stop terminating TLS before the attesting component, or pass the exporter through.

**Fix.** List this as an alternative server contract. Add the relay scenario as an explicit adversarial test.

### M7. Adversarial tests: missing or weak cases (confirmed gaps)

Add these:

- **Evidence relay** through a shared certificate (M6).
- **Rollback:** ATC or github-proxy presents an older signed release (H1).
- **SDK key rotation** during a request, re-attesting to an unapproved release (H1).
- **Pi retries** at the provider and turn layers after a gate failure (M2).
- **Replay to another provider:** user switch, `--models` cycling, and virtual-model fallback (M1).
- **Header leakage**, and a payload hook that adds unclassified fields.
- **Drift in `hardware-measurements` `latest`**, and a TDX MRTD/RTMR0 mismatch.
- **GPU count and topology mismatches**, including Blackwell multi-GPU without switch evidence.
- **compose-manager `env` override**, and a staged-but-not-activated deployment.
- **A `models.json` override** of the provider's `baseUrl`/`compat`.
- **Runtime capability probe failure** under the Bun binary (M3).

Rewrite one existing row. "Router updates backend after a status check" cannot be tested against production; specify a local simulated router built from the pinned `updateModelMeasurements`.

### L1. Small accuracy corrections

- The design links the repository/tag policy at `sigstore.ts#L83`. The policy is at [L86–L91](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/verifier/src/sigstore.ts#L86-L91).
- The existing extension's header comment says the SDK does "no independent AMD signature-chain check" ([L23](https://github.com/tinfoilsh/pi-provider/blob/187fcfc1e04abfc5a44d16bf1523a8a88f38d3ed/tinfoil.ts#L23)). The pinned verifier does check ARK→ASK→VCEK against embedded Genoa roots ([cert-chain.ts](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/verifier/src/sev/cert-chain.ts)). What it lacks is revocation checking. Correct this when auditing the baseline.
- Add OHTTP to the description of NEAR E2EE coverage. Also note that the SDK's all-fields extension is ["intentionally selective"](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/core/e2ee-chat.ts#L93-L99), which supports the design's caution.

## Claims checked and found accurate

| Design claim | What was checked |
| --- | --- |
| Pi extension API is sufficient | `registerProvider`/`createProvider`, [`envApiKeyAuth`](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/ai/src/auth/helpers.ts#L9), `options.fetch` handed to the OpenAI client, and `onPayload` applied before send ([openai-completions.ts L366–L383](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/ai/src/api/openai-completions.ts#L366-L383)). No core change is needed (M1 has an optional upstream hook). |
| 4-hour catalog interval, `pi update --models` skips extensions | [remote-catalog-provider.ts L15](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/core/remote-catalog-provider.ts#L15); `ModelRuntime.create` without extensions in `refreshModelCatalogs`. |
| Tinfoil JS: SEV-only, measured-code equality, attested key bindings | [attestation.ts L20–L24](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/verifier/src/attestation.ts#L20-L24) (report_data[0:32] TLS fingerprint, [32:64] HPKE); `verifyBundle` steps; `compareMeasurements`. |
| Router adopts latest backend release | [`updateModelMeasurements`](https://github.com/tinfoilsh/confidential-model-router/blob/6494b7daab6c89b94fdd41f1f8e05a79a0115b94/manager/manager.go#L929-L970) clears enclaves and re-admits by equality to the latest tag. Router→backend TLS is pinned to the attested fingerprint (`newProxy`). |
| Guest GPU attestation is boot-time; a separate nonce GPU report proves no channel | [gpuattest.go](https://github.com/tinfoilsh/cvmimage/blob/46c2430be746e1ad2d783046252d825a77c3f2b1/tinfoil/cmd/boot/gpuattest.go) sets the GPU ready state only after attestation. NEAR's GPU check is CPU-independent (H2). |
| NEAR shared signing key; reports are not an inventory | [Model attestations doc](https://docs.near.ai/cloud/verification/cloud-api/model-attestations) warning; [direct-inference-client.ts L69–L90](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/core/direct-inference-client.ts#L69-L90). |
| Direct TLS binding: same-connection flow, disabled in the SDK, issue open | [TLS doc](https://docs.near.ai/cloud/verification/direct/tls); [direct-attestation-client.ts](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/node/direct-attestation-client.ts) `includeSpkiFingerprint: false`; [nearai/cloud-api#1087](https://github.com/nearai/cloud-api/issues/1087) is OPEN as of review. |
| cvm-ingress key derivation, S3 restore, export | [entrypoint.sh L19+](https://github.com/nearai/cvm-ingress/blob/c785c6ed8d4ec0bb0ec4bcb45ef7afe3de48b24e/entrypoint.sh#L19), [certs.sh L142](https://github.com/nearai/cvm-ingress/blob/c785c6ed8d4ec0bb0ec4bcb45ef7afe3de48b24e/lib/certs.sh#L142). The archive is encrypted with unauthenticated AES-256-CBC ([lib/crypto.sh](https://github.com/nearai/cvm-ingress/blob/c785c6ed8d4ec0bb0ec4bcb45ef7afe3de48b24e/lib/crypto.sh)), so `lib/crypto.sh` establishes neither archive integrity nor anti-rollback. CBC is malleable. Treating S3 as delivery-only requires authenticated integrity and rollback checks. |
| compose-manager mutability; KMS roles | compose-manager README (deploy, `env`, `dstack-agent/restart`, action log); [near-kms README](https://github.com/nearai/near-kms/blob/dd792a9fa228d33c6dbe615646242d20e9d876a4/README.md) (Owner/DAO roles; allowed compose, OS image, and device lists). |
| NEAR SDK defaults; Node 24 | [`OutOfDate` default](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/core/dstack-attestation.ts#L23-L26); GPU `if-present`; JWKS fetched over HTTPS; [`engines.node >=24`](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/package.json). |

## Deployment facts to record as release gates

These were not verifiable from source. Each must be established for an enabled profile before Approved workloads can be enabled.

1. **Tinfoil**
   - whether workers are publicly reachable and how they authenticate a user API key directly;
   - each worker's CPU platform (SEV Genoa vs TDX);
   - the `hardware-measurements` entries to pin;
   - `nvattest` policy and RIM/OCSP dependencies;
   - the multi-GPU link-encryption assumption on Blackwell;
   - whether the keyserver releases any secret that affects user-content confidentiality (the inspected TLS/HPKE keys are per-boot).
2. **NEAR**
   - which KMS production uses, and who governs it;
   - the actual TLS-key sharing scope;
   - whether production recipes still download weights at runtime with unpinned tooling;
   - who holds compose-manager tokens, and their deploy rules;
   - whether direct endpoints accept user API keys and are reachable;
   - the deployed proxy and nginx topology (whether the plain-HTTP ports are reachable off-host).
3. **Both:** behavior under the Bun binary of the TLS APIs the transport needs.

Written by Claude

Written by Opus 5.5; adapted for publication by Codex.
