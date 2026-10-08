# Opus 5.5 review B: multi-model / SEV-SNP public-build profile and pinned TLS client at `520f0ae` (+ `246891b`)

Reviewed fixed commit [`520f0ae`](https://github.com/ariofrio/pi-tee/commit/520f0ae307e3245adf212bbb3e6b620536fbcec4) (range `df31083..520f0ae`, plus the earlier WASM migration [`dd518cc`](https://github.com/ariofrio/pi-tee/commit/dd518cc) where it touches the scoped files). At the parent's request, the review also covers [`246891b`](https://github.com/ariofrio/pi-tee/commit/246891bed9c27c9791a4c16b179ac436efff6325), which adds local SEV-SNP floors. I used read-only detached worktrees. I sent no inference requests and used no credentials.

Trust model applied: the one declared in [docs/tinfoil-public-profile.md](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/docs/tinfoil-public-profile.md). Named publishers, GitHub, Sigstore, Intel, AMD and NVIDIA are trusted. The attested guest, including the engine image, is trusted. Delivery, discovery, DNS and the host are untrusted.

## Verdict: enable after fixes

The cryptographic chain is sound end to end:
- **SEV-SNP launch digest.** It binds the kernel, initrd, command line (hence the config hash and verity root) and vCPU count, exactly like the TDX RTMR path. I reproduced it with `sev-snp-measure 0.0.12` for all three releases and for edge cases.
- **Pinned OVMF.** It actually enforces the hashes table.
- **GPU evidence and keys.** They are bound to the CPU report.
- **Transport.** It dials only the appraised host and checks the quote-bound SPKI before any byte of HTTP. This holds on Node and Bun.
- **Retry.** The new retry neither widens acceptance nor loops.

One finding blocks SEV-SNP admission as configured:
- **F1 (High): stale Genoa firmware floors.** The publisher's floors, and the "local backstop" `246891b` copies from them, admit Genoa firmware older than AMD's fix for a High-severity SEV-SNP break. The three live Gemma Genoa workers run firmware below AMD's current SEV-SNP mitigations today.

Also required:
- **F2 (Medium): undeclared plaintext recipient.** The serving contract omits a plaintext reverse proxy in the engine image. The design document requires every remote recipient to be named.
- **F3 (Low, cheap): Node crash on malformed response headers.** A malformed response header from the pinned peer crashes the Node process.

Everything else is Low or Info.

## Findings

| # | Severity | Status | Finding |
| --- | --- | --- | --- |
| F1 | **High** | CONFIRMED (policy values, live probe, AMD bulletins) | SEV-SNP Genoa TCB floors (publisher `amd-genoa-prod` and the `246891b` local backstop: SNP SPL 14, µcode 72, build 21) are below AMD-SB-3019 (CVE-2024-56161, SPL 0x17/µcode 0x54). The live Gemma Genoa workers (SPL 23/µcode 84, FW 1.55.40) are below AMD-SB-3020 (CVE-2025-0033, SPL 0x1B) and AMD-SB-3027 (CVE-2025-29943, µcode ≥ 0x56). |
| F2 | Medium | CONFIRMED (signed provenance, sidecar source) | The engine image's entrypoint is not checked. DeepSeek's entrypoint is `/opt/tinfoil/inference-sidecar vllm serve`, a plaintext reverse proxy that also rewrites vLLM's argv. The contract says "no sidecar" and omits it from the plaintext closure. |
| F3 | Low | CONFIRMED (Node 26.10; Bun differs) | `pinned-tls.ts` throws from a socket `data` listener on an invalid response header name or value. Node treats it as an uncaught exception and the process exits. |
| F4 | Low | CONFIRMED | The response `ReadableStream` has no backpressure. While the consumer stalls, the pinned peer can make the client buffer without limit. 200 MiB was buffered behind the "32 MiB" limiter. |
| F5 | Low | Client behavior CONFIRMED; exploit PLAUSIBLE | A close-delimited body is accepted as complete at a TCP close without TLS `close_notify`, which permits on-path truncation if the server ever omits framing. EHBP has no authenticated end of stream (prior F9). |
| F6 | Low | CONFIRMED (Bun 1.3.13) | Bun ignores `minVersion: "TLSv1.3"` and negotiates TLS 1.2. The pin still holds; the documentation claims TLS 1.3. |
| F7 | Low | CONFIRMED | The user-visible `direct-public` route assumptions are stale: they claim Intel only, Gemma only and "exactly one Hopper". The package README omits single-GPU Blackwell in SPT mode. |
| F8 | Info | — | `authorityPolicyDigest` does not cover rules enforced in JavaScript: the NVIDIA claim list, mode mapping, expiry formula and host/key selection. |
| F9 | Info | — | Any candidate failure clears the shared artifact cache, so a bogus discovered host forces every model to download artifacts again. |

### F1 — SEV-SNP Genoa floors predate AMD's SEV-SNP fixes, and the live Genoa fleet is unpatched against two of them

**Raw evidence**

1. **The publisher policy.** It is the signed `platform-endorsements` `v0.0.16` predicate carried in the private SNP fixture (`local-amd-evidence.json`, collateral `platform`). It contains:
   - `amd-genoa-prod`: `minimum_build 21`, `minimum_api_version "1.55"`, `minimum_tcb {bl 7, tee 0, snp 14, ucode 72}`, and the same values for `minimum_launch_tcb`. `amd-genoa-dev` has the same floors.
   - `amd-turin-prod`: `{fmc 1, bl 1, tee 1, snp 4, ucode 82}` with API 1.58.
2. **The `246891b` local floors** are the same values: [release.go#L109-L115](https://github.com/ariofrio/pi-tee/blob/246891bed9c27c9791a4c16b179ac436efff6325/tools/tinfoil-public-build/release.go#L109-L115) and [public-policy.ts#L20](https://github.com/ariofrio/pi-tee/blob/246891bed9c27c9791a4c16b179ac436efff6325/packages/tinfoil/src/public-policy.ts#L20). Their source is the [tinfoil-go `05e8179` hard-coded values](https://github.com/tinfoilsh/tinfoil-go/blob/05e817920780362d6c79b0035902d51bd608918b/verifier/attestation/sev.go#L219-L230). The CHANGELOG states: "Current publisher floors already equal them."
3. **AMD's bulletins** (fetched 2026-10-08):
   - [AMD-SB-3019](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3019.html), CVE-2024-56161, CVSS 7.2 High. Malicious microcode leads to "loss of confidentiality and integrity of a confidential guest running under AMD SEV-SNP". Genoa fix: SEV FW 1.55.40, `TCB[SNP] = 0x17`, µcode `0x0A101154`. Genoa-X: `0x0A10124F`.
   - [AMD-SB-3020](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3020.html), CVE-2025-0033 (RMP initialization). Genoa fix: SEV FW hex 1.37.31 (`SPL=0x1B`) plus µcode `0x0A101156` (Genoa-X `0x0A101251`), or GenoaPI 1.0.0.H. Turin fix: `SPL=0x04`, µcode `0x0B002150`.
   - [AMD-SB-3027](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3027.html), CVE-2025-29943 (requires an SMT sibling). Floors: Genoa `TCB[MICROCODE] >= 56`, Genoa-X `>= 51`, Turin `>= 51` (all hex).
   - The microcode TCB value is the low byte of the µcode revision, per SB-3027's "TCB Value for Attestation" column. µcode 72 is therefore `0x48`, below 0x54.
4. **Live probe**, 2026-10-08. I fetched `/.well-known/tinfoil-attestation` with my own nonces from every host that `inference.tinfoil.sh` advertised, and parsed the reported TCB:

   | Hosts | Platform | FW | Reported TCB |
   | --- | --- | --- | --- |
   | `gemma4-31b-inf6-{3,4,5}` | SNP Genoa (`19/11/01`) | 1.55.40 | bl 10, tee 0, **snp 23 (0x17), ucode 84 (0x54)**; `platform_info` SMT enabled |
   | `glm-5-3-inf{17,18,20,21}` | SNP Turin (`1a/02/01`) | 1.58.3 | fmc 1, bl 3, tee 2, snp 5, ucode 97 |
   | `gemma4-31b-inf8-*`, `deepseek-v4-1-flash-inf16` | TDX | — | — |

**Trace.** `floorSNPArtifact` (`246891b`) raises only to the values above. tinfoil-go turns the floors into go-sev-guest options ([expectations.go#L175-L227](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/quote/sev/expectations.go#L175-L227)). go-sev-guest then requires `minimum ≤ reported = VCEK-cert TCB ≤ current` and `minLaunch ≤ launch`. Nothing else constrains SNP firmware: AMD has no UpToDate verdict.

**Conclusions**

- **EntrySign is admitted.** A Genoa host on pre-SB-3019 firmware (for example SNP SPL 0x16, µcode 0x53) satisfies every check, given a VCEK that AMD's KDS issues for that TCB. Its operator can load malicious microcode. That defeats SEV-SNP confidentiality for the guest that holds the prompt and keys. The TDX path would reject an equivalent out-of-date platform through Intel's UpToDate verdict, so the two platforms are not at parity, contrary to the CHANGELOG's "matching the existing TDX floors".
- **The live Gemma Genoa workers are below current AMD mitigations today.** This is not hypothetical. With production enabled, a random share of Gemma dispatches would go to hosts lacking the CVE-2025-0033 fix. CVE-2025-0033 lets a malicious hypervisor write the RMP during SNP initialization and undermine guest memory integrity. The same hosts lack the CVE-2025-29943 µcode, and SMT is enabled on them. The Turin GLM workers meet both bulletins.
- **Shape-based Genoa/Turin selection cannot be abused** (the parent's question). `floorSNPArtifact` picks floors from the publisher policy's `fmc_spl` presence and rejects launch/current shape mismatches ([release.go#L154-L157](https://github.com/ariofrio/pi-tee/blob/246891bed9c27c9791a4c16b179ac436efff6325/tools/tinfoil-public-build/release.go#L154-L157)). tinfoil-go then requires `fmc_spl` for Turin and forbids it for Genoa ([expectations.go#L157-L174](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/quote/sev/expectations.go#L157-L174)). It takes the product line from the signed report's CPUID, verified under that product line's ARK ([authenticate.go#L109-L121](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/quote/sev/authenticate.go#L109-L121), [#L240-L247](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/quote/sev/authenticate.go#L240-L247)). Bergamo/Siena and Turin Dense map to "unknown" and are rejected. A mismatched shape therefore fails closed.
- **The selection is too coarse for correct µcode floors.** Microcode SPL numbering is per stepping: Genoa `0x0A1011xx` versus Genoa-X `0x0A1012xx`, both reported as product "Genoa". Any single Genoa µcode floor is either too strict for Genoa-X or too weak for Genoa.

**Correction**

1. **Raise the local Genoa floors now to at least AMD-SB-3019:** SNP SPL ≥ 0x17, build ≥ 40 at API 1.55, µcode ≥ 0x54. Use µcode ≥ 0x4F for Genoa-X stepping 2. This costs nothing: the live Genoa workers already meet it.
2. **Decide explicitly on SB-3020 and SB-3027** (SNP SPL ≥ 0x1B, µcode ≥ 0x56/0x51). Enforcing them today drops `gemma4-31b-inf6-*` and leaves Gemma on TDX. Not enforcing them must be recorded in the serving contract as accepted CVE-2025-0033/29943 exposure on Genoa.
3. **Key µcode floors on the authenticated report CPUID** (family/model/stepping, report bytes `0x188-0x18A`), not on the publisher policy shape. Add a test with live Genoa TCB values that pins the decision.
4. **Document the maintenance duty.** The AMD row of the contract should say that SNP floors must track AMD bulletins, because nothing plays Intel's UpToDate role.

### F2 — The engine image's entrypoint and environment are outside the runtime profile; DeepSeek's entrypoint is an undeclared plaintext proxy

**Raw evidence**

- **The image's entrypoint is a Tinfoil proxy.** The signed OCI config for DeepSeek v0.0.3 ([testdata/deepseek-v0.0.3-config.json](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/tools/tinfoil-public-build/testdata/deepseek-v0.0.3-config.json)) has `Entrypoint ["/opt/tinfoil/inference-sidecar","vllm","serve"]`. The Dockerfile embedded in the signed BuildKit provenance has `FROM ghcr.io/tinfoilsh/inference-sidecar@sha256:65ce23d6…` and `COPY --from=sidecar /inference-sidecar /opt/tinfoil/inference-sidecar`. Gemma's entrypoint is plain `vllm serve`.
- **The proxy reads plaintext and rewrites argv.** [inference-sidecar `main.go`](https://github.com/tinfoilsh/inference-sidecar/blob/d30bcf700f10202615e1477a6292546d614ce60c/main.go#L51-L131) (current `main`; the deployed digest is not mapped to a commit by the verifier):
  - It listens on the configured `--port`.
  - It appends `--host 127.0.0.1 --port 18001` to vLLM's argv.
  - It reverse-proxies every request.
  - It reads up to 8 MiB of each POST body ([#L140-L160](https://github.com/tinfoilsh/inference-sidecar/blob/d30bcf700f10202615e1477a6292546d614ce60c/main.go#L140-L160)) and rewrites SSE chunks for usage metering and padding.
  - It honors `SIDECAR_LISTEN` and `SIDECAR_UPSTREAM_PORT` from the environment.
- **The verifier does not check any of this.** `authenticateContainer` decodes only `architecture`, `os` and `config.Labels` from the image config ([container.go#L185-L194](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/tools/tinfoil-public-build/container.go#L185-L194)). `Entrypoint`, `Cmd`, `Env` and `WorkingDir` are never examined. The `tinfoil-vllm-v1` allowlist ([runtime.go#L208-L312](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/tools/tinfoil-public-build/runtime.go#L208-L312)) assumes vLLM's argparse semantics.
- **The contract says otherwise.** It states: "One engine container and no sidecar or decrypting router are admitted by the configuration profile." Its plaintext closure lists only the guest components and "the authenticated inference engine and its libraries/tokenizer/templates" ([tinfoil-public-profile.md#L33](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/docs/tinfoil-public-profile.md#L33), [#L39](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/docs/tinfoil-public-profile.md#L39)). [design.md#L38](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/docs/design.md#L38) requires that remote recipients, "including … sidecars", "cannot remain implicit".

**Conclusions**

- **No confidentiality break under the declared trust model.** The sidecar is inside the workload-publisher-endorsed image and has no egress network. It shows no sign of logging or exporting bodies: `log.Printf` appears only on padding and re-encoding errors.
- **The closure is still under-declared.**
  - It is a plaintext recipient built from a separate repository, `tinfoilsh/inference-sidecar`, whose provenance the client does not authenticate.
  - The answer to "can any accepted flag or env var enable egress, remote code, logging or alternative model loading?" is **no for vLLM's semantics as allowlisted**: I checked every accepted flag and environment value. But the first argv consumer is an unpinned entrypoint, and the image's `Env` is publisher-chosen. Any guarantee about flags is therefore relative to those unverified fields.

**Correction**

1. **Name the sidecar in the contract.** Add it to the plaintext closure and the recipient inventory. Name `tinfoilsh/inference-sidecar` as a dependency trusted through the workload publisher.
2. **Constrain the image config in the profile.** Either require `Entrypoint ∈ {["vllm","serve"], ["/opt/tinfoil/inference-sidecar","vllm","serve"]}`, `Cmd` empty and no unexpected `Env` keys, or state that the image config is trusted wholesale. Then the flag analysis is anchored to a known consumer.

### F3 — Node process crash on a malformed response header from the pinned peer

[pinned-tls.ts#L91-L95](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/core/src/pinned-tls.ts#L91-L95) calls `headers.append(...)` inside the socket `data` handler without a `try`. The WHATWG `Headers` constructor throws `TypeError` for a name containing a space, or a value containing a bare LF or NUL.

Reproduced with a synthetic P-384 server pinned by the client (probe kept under the main checkout's `.scratch/work/review-snp-tls/`):

| Response header line | Node 26.10 | Bun 1.3.13 |
| --- | --- | --- |
| `Bad Name: x` | `TypeError: Headers.append: "Bad Name" is an invalid header name.`, **process exit 1** | `TEE_CONNECTION_FAILED` |
| `X: a\nTransfer-Encoding: chunked` | uncaught `TypeError`, exit | `TEE_CONNECTION_FAILED` |
| `X: a\0b` | uncaught `TypeError`, exit | — |

Only the holder of the attested TLS key can send these bytes, so the impact is availability: the user's Pi process dies. **Correction:** wrap header construction in the existing `fail()` path, or validate names and values with token/field-value regexes before calling `append`. Add the three cases to `tests/pinned-tls.test.ts`.

### F4 — No backpressure: buffering is unbounded behind the "bounded" limiter

**Code.**
- `bodyStream` enqueues on every socket `data` event and has no `pull` ([pinned-tls.ts#L120-L173](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/core/src/pinned-tls.ts#L120-L173)).
- `limitResponseBody` counts only the bytes that pass through its `TransformStream` ([transport.ts#L7-L25](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/core/src/transport.ts#L7-L25)).

**Observation.** The pinned peer streamed 200 MiB of chunked body while the consumer read one chunk and stalled, with the production `limitResponseBody(…, MAX_ENCRYPTED_RESPONSE_BYTES)` in the path. Node RSS reached 252 MiB, the server finished sending, and no error was raised. The contract's "bounded bodies" ([tinfoil-public-profile.md#L74](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/docs/tinfoil-public-profile.md#L74)) holds for consumed bytes, not for memory.

**Correction.** Call `socket.pause()` when `controller.desiredSize <= 0` and resume in `pull()`. Alternatively, cap the queued bytes and error the stream.

### F5 — Close-delimited bodies accepted without `close_notify`

[pinned-tls.ts#L163-L168](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/core/src/pinned-tls.ts#L163-L168) closes the stream successfully when the socket closes and the response had neither `Content-Length` nor chunked framing.

**Observation.** A server that destroyed the TCP connection without `close_notify` produced `status=200 body="first-part"` on both Node and Bun.

**Exposure.** An on-path attacker can inject a FIN and truncate such a body undetected, because EHBP has no authenticated end marker (prior review F9). Go's `net/http` frames HTTP/1.1 responses with chunked encoding, so the shim is not expected to send close-delimited bodies. The exploit therefore needs the attested server to omit framing; I did not observe it doing so. Rated PLAUSIBLE.

**Correction.** Reject responses that are neither chunked nor length-framed. This single-purpose client talks only to known Go servers.

### F6 — Bun does not enforce TLS 1.3

Against a server capped at TLS 1.2, Node rejected the connection (`TEE_CONNECTION_FAILED`), but Bun 1.3.13 completed it and returned `200 ok`. This contradicts `minVersion: "TLSv1.3"` at [pinned-tls.ts#L26](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/core/src/pinned-tls.ts#L26) and the contract's "TLS 1.3 SPKI".

The SPKI pin remains sound: a TLS 1.2 ECDHE-ECDSA handshake still proves possession of the key, and BoringSSL does not renegotiate by default. `bun test tests/pinned-tls.test.ts` passes (2/2), so pin-before-write holds under Bun.

**Correction.** After `secureConnect`, require `socket.getProtocol() === "TLSv1.3"` before writing.

### F7 — Stale user-visible assumptions

[index.ts#L30-L37](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/tinfoil/src/index.ts#L30-L37) (route `direct-public`) still states:
- "Intel roots … authenticate"
- "the constrained Gemma runtime configuration"
- "Exactly one CPU-bound Hopper report must pass … SPT"

The same route appraises AMD SEV-SNP and up to eight Blackwell GPUs in MPT for three models. The report users see therefore omits AMD as an authority. The production profile's assumptions ([public-session.ts#L53-L62](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/tinfoil/src/public-session.ts#L53-L62)) are current.

[packages/tinfoil/README.md#L9](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/tinfoil/README.md#L9) says "One Hopper GPU must report SPT; several Blackwell GPUs must report MPT". The code also admits a single Blackwell GPU in SPT ([gpu-policy.ts#L39-L43](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/tinfoil/src/gpu-policy.ts#L39-L43)).

### F8 and F9 — Info

- **F8.** [public-policy.ts#L9-L41](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/tinfoil/src/public-policy.ts#L9-L41) hashes authorities, floors, WASM digests and firmware constants. Rules enforced only in JavaScript (`REQUIRED_CLAIMS`, the SPT/MPT mapping, the expiry formula and the key-item selection) can change without changing `authorityPolicyDigest`. Either include a rules version or say in the doc that the digest covers authorities only.
- **F9.** [public-build.ts#L225-L228](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/tinfoil/src/public-build.ts#L225-L228) clears the process-wide cache on any failure. Every candidate rejected in [public-session.ts#L28-L40](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/tinfoil/src/public-session.ts#L28-L40) therefore forces the next one to download everything again. This affects availability only.

## Verified correct (scope items 1–7)

| Item | Result and evidence |
| --- | --- |
| SNP launch-digest port | **Matches the reference.** `uv run --with sev-snp-measure==0.0.12 sev-snp-measure --mode snp --vcpu-type EPYC-v4 --guest-features 0x1` with `OVMF.fd` (SHA256 `3a38d062…1c9f`) reproduces the signed `snp_measurement` of Gemma v0.0.25 (16 vCPU), GLM v0.0.3 and DeepSeek v0.0.3 (32 vCPU). It also matches [snp-measurement.ts](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/tinfoil/src/snp-measurement.ts) for 1/2/64/511 vCPUs, an empty initrd and empty, UTF-8 and double-space command lines. |
| SNP binds config hash and command line like TDX | **Yes.** The hashes table (`sha256(cmdline‖NUL)`, initrd, kernel) is measured in the launch digest. Node passes `expectedCommand`, which contains `roothash=` and `tinfoil-config-hash=` ([public-build.ts#L127-L146](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/tinfoil/src/public-build.ts#L127-L146)). The pinned OVMF is built from [`OvmfPkg/AmdSev/AmdSevX64.dsc`](https://github.com/tinfoilsh/edk2/blob/3b2f00a4846ad2fc3655c652a16367589a3730ec/.github/workflows/release.yml), which links `BlobVerifierLibSevHashes` into `QemuKernelLoaderFsDxe` ([dsc#L170](https://github.com/tinfoilsh/edk2/blob/3b2f00a4846ad2fc3655c652a16367589a3730ec/OvmfPkg/AmdSev/AmdSevX64.dsc#L170), [#L647-L649](https://github.com/tinfoilsh/edk2/blob/3b2f00a4846ad2fc3655c652a16367589a3730ec/OvmfPkg/AmdSev/AmdSevX64.dsc#L647-L649)), so mismatched blobs do not boot. The fork's only DSC change from upstream is `CcProbeLib`. The predicate's `snp_measurement` equals the report measurement (`sevLaunchDigest` → `opts.Measurement`, with exact guest-policy and platform-info equality and VMPL 0). Recomputed digest = predicate = quote. The debug OVMF's serial output is disclosed ([profile#L41](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/docs/tinfoil-public-profile.md#L41)). |
| Subject equals predicate, single bundle | `authenticateDeployment` strictly decodes the subject and `DeepEqual`s it to the predicate ([release.go#L58-L73](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/tools/tinfoil-public-build/release.go#L58-L73)). `verify` requires exactly one `code` sigstore-code entry and returns predicate registers bound by `Assemble`. Each subcommand's `codeStatementDigest` must match. Prior review F1 is closed. |
| GPU appraisal | Per device: nonce, single `hwmodel`, matching arch, `measres`, debug disabled, secure boot, distinct `ueid`, every required claim, three valid good nonce-matched OCSP chains, and the authenticated mode parsed from the NVIDIA-verified report bytes. Count equals the `gpus` measured in the release (also equal to `vm_shape.gpus`). Hopper is limited to one GPU in SPT; Blackwell multi-GPU requires MPT; PPCIe is rejected ([worker-appraisal.ts#L53-L105](https://github.com/ariofrio/pi-tee/blob/520f0ae307e3245adf212bbb3e6b620536fbcec4/packages/tinfoil/src/worker-appraisal.ts#L53-L105)). Order between claims and evidence cannot matter, because every claim and every report must pass. |
| GPU evidence and key binding | tinfoil-go strictly parses the envelope (canonical base64, no duplicate or unknown members, unique crypto and device item ids). It hashes the decoded `crypto_material` and `device_evidence` into `REPORT_DATA`. Node reads the same bytes; a duplicate `tls`/`hpke` id is impossible. Any attempt to inject JSON into the helper input through `raw` is rejected twice: by Node `JSON.parse` and by Go duplicate/unknown-key rejection. |
| Expiry | `min(checkedAt+60 s, challengeAt+300 s, freshness+7 d)` is rechecked by the provider, by the guarded fetch, and after TLS connect before the write. |
| Discovery and transport | Discovery only orders candidates. Each candidate gets a fresh nonce and full appraisal, and `build.repo` must equal the requested model's repository. The logical `.invalid` base URL is enforced by `request.url === addressed`. `pinnedTlsFetch` dials only `https://${appraisedHost}/v1/chat/completions` and checks the SPKI, then the expiry, before the first write. The send-once flag is set before encryption. The ehbp 0.3.3 `forwardedRequestInit` keeps `signal`, so abort reaches the socket. |
| Request smuggling and injection | `Headers` rejects CR, LF and NUL. Hop-by-hop and framing headers are dropped. `Content-Length` is computed locally, with `Connection: close` and one request per connection. Duplicate or conflicting response `Content-Length` and unknown `Transfer-Encoding` values reject. |
| Runtime allowlist | Under vLLM's argparse semantics (Gemma pins v0.25.1; DeepSeek uses a dedicated upstream tag), no accepted flag or env var enables egress, remote code, request logging, adapters or alternative weights. `--model` and speculative `model` are restricted to measured pack mounts; `--load-format` excludes `tensorizer` and `dummy`; there are no `--tokenizer`, `--hf-overrides`, `*-plugin`, `--trust-remote-code`, `--enable-log-*` or `--config` flags; JSON flags carry bounded scalar keys only; env values are exact or numeric. A flag value can never start with `-`, so argv desynchronization is impossible. F2 qualifies this conclusion. |
| OCI 1.1 attestation and optional `SOURCE_REVISION` | The subject must equal the engine descriptor (digest and size) and the config the inline empty object. `SOURCE_REVISION`, when present, must equal the label/VCS revision, which stays mandatory. |
| `get()` retry | Retries only 502/503/504, at most twice, with abortable 0.5 s and 1 s delays, and cancels each discarded body. Final bytes go through the same digest and signature checks. The test asserts exactly 3 attempts and then rejection. |
| Reproducibility and tests | I rebuilt the `246891b` helper WASM offline with Go 1.26.6 (`-trimpath -buildvcs=false`, vendored, patched in-toto). It gives `15c66efc…6fb5`, equal to the pin. These all pass at both commits: `go test`/`go vet`; `public-build-chain.test.ts` with the private **SEV-SNP** and **TDX** fixtures, including every substituted-artifact negative; the SNP, GPU and pinned-TLS suites (Node), and `bun test tests/pinned-tls.test.ts`. |

## Documentation claims versus enforcement

| Claim | Status |
| --- | --- |
| "Local floors" backstop SNP publisher floors, "matching the existing TDX floors" (`246891b`) | **Overstated** (F1). The SNP floors do not cover AMD-SB-3019, SB-3020 or SB-3027 for Genoa; TDX has Intel's UpToDate verdict. |
| "One engine container and no sidecar … admitted" | **Incorrect for DeepSeek** (F2). The engine runs an in-image plaintext proxy. |
| Profile "checks the value of every allowed engine flag and environment variable" | True for `tinfoil-config.yml`. Image `Env` and `Entrypoint` are not checked (F2). |
| "TLS 1.3 SPKI is checked on the actual socket" | SPKI is checked on Node and Bun. TLS 1.3 is not enforced on Bun (F6). |
| "Streaming output … with bounded bodies" | Bounded in bytes consumed, not in memory (F4). |
| `direct-public` route assumptions | Stale (F7). |
| The SEV-SNP launch digest binds the boot inputs like RTMR1/RTMR2 | **Supported** (reproduced; OVMF enforcement traced). |

## Conditions for enablement

1. **F1.** Raise local Genoa floors to at least AMD-SB-3019 (no availability cost today) and key µcode floors on the authenticated report stepping. Then either enforce SB-3020/3027 (dropping the three Genoa Gemma workers until Tinfoil patches), or record the accepted exposure explicitly in the serving contract and the authority policy. Add a note that SNP floors must follow AMD bulletins.
2. **F2.** Declare `inference-sidecar` as a plaintext recipient and publisher dependency. Either constrain the image config's `Entrypoint`, `Cmd` and `Env`, or state that the image config is trusted wholesale.
3. **F3.** Catch header-construction errors in `readResponse` and add regression tests.
4. **Recommended before or soon after enablement:** F4 (backpressure), F5 (reject close-delimited bodies), F6 (assert TLS 1.3), F7 (refresh the assumption text and README). F8 and F9 are optional.

Written by Claude
