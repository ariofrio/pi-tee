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

## Re-review at `ad71a91` (fixes `0e3add3`, `ea382e6`, `8b33709`)

Reviewed [`246891b..ad71a91`](https://github.com/ariofrio/pi-tee/compare/246891bed9c27c9791a4c16b179ac436efff6325...ad71a91f007a78c75942fddb948a306f99a4fc15) in a fresh detached worktree, under the same rules as above. The commits are [`8b33709`](https://github.com/ariofrio/pi-tee/commit/8b337098382433c6827e09376aaec995ad95da28) (SNP floors, production policies, engine image, authority digest, assumptions), [`0e3add3`](https://github.com/ariofrio/pi-tee/commit/0e3add314af18112522bad2321d83ce8eb70af14) (TLS client) and [`ea382e6`](https://github.com/ariofrio/pi-tee/commit/ea382e6c5927ef3d62292c136d9e7e86dd801cd0) (reachability probe). The in-repo copy of this report (`docs/reviews/`) predates this section.

### Verdict: enable

All three enablement conditions are met. The remaining items are Low or Info, can only affect availability, and only the attested peer or delivery can trigger them.

### Status of each finding

| # | Status | Evidence |
| --- | --- | --- |
| F1 | **Fixed** | Floors are now keyed on the authenticated report CPUID (`snpCPU` reads report bytes `0x188-0x18A` and requires version ≥ 3 and 1184 bytes): Genoa B1 `19/11/01` SPL 0x1B/µcode 0x56, Genoa-X `19/11/02` 0x1B/0x51, Turin C1 `1a/02/01` 0x04/0x51. These meet AMD-SB-3019, SB-3020 and SB-3027. Other CPUs are rejected, and the policy shape must match the CPU ([release.go#L127-L201](https://github.com/ariofrio/pi-tee/blob/ad71a91f007a78c75942fddb948a306f99a4fc15/tools/tinfoil-public-build/release.go#L127-L201)). Observed: the same live Genoa evidence (`local-amd-evidence.json`, SPL 23/µcode 84) passes the helper at `246891b` and fails at `ad71a91` with `TEE_CPU_POLICY_REJECTED`. Fresh evidence checked with the `ad71a91` helper under my own nonces: `gemma4-31b-inf6-3` (Genoa) rejected; `glm-5-3-inf17` (Turin), `gemma4-31b-inf8-0` and `deepseek-v4-1-flash-inf16` (TDX) accepted. `glm-5-3-inf20/21` are rejected at both commits because the platform publisher does not endorse their CHIP_IDs, as the docs state. The AMD contract row now names the bulletins and the duty to raise floors. |
| Shape-based selection | **Removed** | Selection no longer uses the publisher policy's shape. A mismatched shape is rejected locally and again by tinfoil-go. |
| Non-production policies (new) | **Correct** | `productionPolicy` requires the matched policy name to end in `-prod`, for TDX and SNP. This is a naming backstop, not an authority: the publisher names its policies. Live TDX and Turin policies are `*-prod`. |
| F2 | **Fixed** | `checkEngineImageConfig` ([container.go#L330-L370](https://github.com/ariofrio/pi-tee/blob/ad71a91f007a78c75942fddb948a306f99a4fc15/tools/tinfoil-public-build/container.go#L330-L370)) strictly decodes the image config, rejecting duplicate and case-variant keys, so Docker's lenient decoder cannot see different values. It requires `Entrypoint` ∈ {`vllm serve`, `/opt/tinfoil/inference-sidecar vllm serve`}, empty `Cmd`, `User`, `Volumes`, `Shell`, `OnBuild` and `Healthcheck`, and allowlisted `Env` names. `SIDECAR_*` and `VLLM_*` behavior switches are excluded; `PYTHONPATH` must be exactly `/opt/tinfoil`. `PATH` and `LD_LIBRARY_PATH` values are unconstrained, but they only select files inside the publisher-endorsed image. The contract now names `inference-sidecar` and `tinfoil_usage` as plaintext recipients trusted through the workload publisher, and the authority digest records the entrypoints. |
| F3 | **Fixed** | Names must match `token`, values `field-value`, and `append` is wrapped ([pinned-tls.ts#L96-L102](https://github.com/ariofrio/pi-tee/blob/ad71a91f007a78c75942fddb948a306f99a4fc15/packages/core/src/pinned-tls.ts#L96-L102)). My original probes (invalid name, bare LF, NUL, space before colon) now return `TEE_RESPONSE_REJECTED` on Node and Bun, with no crash. Obsolete folding is rejected too. |
| F4 | **Fixed on Node; partial on Bun** | The stream now has a 1 MiB byte high-water mark and `pause()`/`pull()→resume()`. Node: 0/8 failures of the repo's backpressure test; my in-process flood stalled the peer at 3–6 MiB in 6/6 runs. **Bun 1.3.13:** the repo's own test `a stalled consumer applies backpressure to the pinned peer` failed 2/15 runs in isolation, and once each in two full-file runs. The failures read "the peer pushed 268435456 bytes while the consumer stalled", and again at 213909504 bytes. Instrumentation shows no JavaScript `data` event while paused, yet the Node peer finished writing up to 256 MiB. One run measured client RSS at 251 MiB, and the bytes later arrived intact and in order. So Bun's native socket layer sometimes keeps reading after `pause()`. This is not a data-integrity issue, and only the attested peer can trigger it. **Recommendation (Low):** add a runtime-independent cap, for example error and destroy when bytes received minus bytes consumed exceeds a limit, or treat the test as Node-only and document the Bun gap. The test is flaky in Bun CI as written. |
| F5 | **Fixed** | Responses must be chunked or carry a valid `Content-Length`, and close before the end is always `TEE_CONNECTION_FAILED` ([pinned-tls.ts#L121-L124](https://github.com/ariofrio/pi-tee/blob/ad71a91f007a78c75942fddb948a306f99a4fc15/packages/core/src/pinned-tls.ts#L121-L124)). My close-without-`close_notify` probe is now rejected on both runtimes. |
| F6 | **Fixed** (with a correction to my original evidence) | `socket.getProtocol() !== "TLSv1.3"` rejects before resolve, and therefore before any write. **Correction:** my original Bun probe hosted the "TLS 1.2" server in Bun, which also ignores `maxVersion`, so that handshake was really TLS 1.3. Re-tested properly against a Node peer capped at TLS 1.2: a plain Bun client with `minVersion: "TLSv1.3"` connects at `TLSv1.2`, so the F6 conclusion stands. The fixed `pinnedTlsFetch` now rejects with `TEE_TLS_KEY_REJECTED` on Bun (`TEE_CONNECTION_FAILED` on Node) and accepts a TLS 1.3 peer on both. The repo's new tests use a Node peer for exactly this reason. |
| F7 | **Mostly fixed** | `direct-public` now reuses the profile's assumptions. [packages/tinfoil/README.md#L9](https://github.com/ariofrio/pi-tee/blob/ad71a91f007a78c75942fddb948a306f99a4fc15/packages/tinfoil/README.md#L9) still says "One Hopper GPU must report SPT; several Blackwell GPUs must report MPT", omitting single-GPU Blackwell in SPT (Info). The profile assumption "AMD's current SEV-SNP bulletin fixes" ages silently; naming SB-3019/3020/3027 would be exact (Info). |
| F8 | **Fixed** | The authority digest now includes the required claims, certificate chains, expiry formula, entrypoints, per-CPU floors and the `*-prod` rule. |
| F9 | Accepted as is | — |

### New code in `ea382e6`

[`reachableHosts`](https://github.com/ariofrio/pi-tee/blob/ad71a91f007a78c75942fddb948a306f99a4fc15/packages/tinfoil/src/public-session.ts#L27-L38) opens a plain TCP connection to port 443 of each discovered host. Hosts are limited to `*.tinfoil.containers.tinfoil.dev`, discovery returns at most 128, and each probe has a 3 s timeout and honors abort. Sockets are destroyed without sending data.

The probe only filters and orders candidates. Each remaining candidate still gets a fresh nonce and full appraisal, the four-attempt cap is unchanged, and an empty reachable set yields `TEE_PUBLIC_BUILD_DEPLOYMENT_UNAVAILABLE`. Nothing is authorized by reachability. The only cost is up to 128 parallel DNS lookups and connections per dispatch (Info).

### Re-run results at `ad71a91`

- `go test ./...` and `go vet ./...` pass, including the new SNP-floor, production-policy and engine-image tests.
- Typecheck is clean, and `npm test` reports 81 pass, 0 fail, 3 skipped (private fixtures).
- `public-build-chain.test.ts` passes with the private TDX evidence. With the private Genoa evidence it now fails with `TEE_PUBLIC_BUILD_REJECTED`, which is expected (F1).
- The SNP digest and GPU suites pass.
- The helper WASM reproduces offline (Go 1.26.6, vendored, patched in-toto): `7877fe36da37652692f56711b263c74fc496963228b7c8c86c537f9ce13a428e`, equal to the pin.

### Consequence to note

With F1 fixed, Gemma is served only by its TDX workers until Tinfoil patches the Genoa hosts. GLM-5.3 stays on endorsed Turin workers, and DeepSeek on TDX.

## Enablement review at `94b43a7`

This section reviews the proposed enablement commit `94b43a7` ("Enable the Tinfoil public-build profile"). It sits on the local, unpushed branch `ariofrio/enable-public-builds`, based on main [`6ea1329`](https://github.com/ariofrio/pi-tee/commit/6ea1329a502467d51e1cbee98c6620a874a9c16c). In my scope I also reviewed [`ecc5cd0`](https://github.com/ariofrio/pi-tee/commit/ecc5cd0) (Bun buffering cap, probe limits) and `6ea1329` (stalled-consumer test). The NVIDIA verifier, WASI and bridge commits `37eba73..13b116f`, including the new `nvattest.wasm` pin `c4bbe723…`, belong to review A and I did not review them. I used a read-only detached worktree, sent no inference requests and used no credentials.

### Verdict: enable (approve the merge), with two conditions before pushing

1. **Review A must have signed off on the post-`ad71a91` NVIDIA verifier commits** (`37eba73..13b116f`, `nvattest.wasm` `c4bbe723…`). Line 13 of the contract now states "Both reviewers re-checked the fixes before production admission was enabled". For this review it is true for the CPU/release, SNP, session and TLS code through `94b43a7`.
2. **Run the production live suite on this exact commit** for all three models under Node and the Bun-compiled Pi before pushing. Expect Gemma on TDX workers only.

### The enablement commit

- **Code change.** The only code change is `PUBLIC_BUILD_PROFILE_ENABLED = true` (`packages/tinfoil/src/public-policy.ts:55-58` at `94b43a7`). It is a constant, not an environment switch.
- **What it activates.** It wires `PUBLIC_BUILD_PROFILE` for the `auto` and `direct-public` routes only (`packages/tinfoil/src/index.ts:48`). Under `public-builds`:
  - The picker lists only catalog models that the profile covers (`selectableCatalog`, provider.ts#L277-L281).
  - The report shows the profile's assumptions.
  - Dispatch goes only through `openSession`, which re-checks profile, model, authority digest, artifact digests, `checkedAt` and `expiresAt`. A model outside the profile fails with `TEE_MODEL_UNAVAILABLE` before any network or SDK call.
  - `router` and `direct` still have no profile, so `public-builds` stays unavailable on them. `approved` stays empty.
- **Activation test** (`tests/tinfoil-intel.test.ts`). It asserts the picker list and the profile assumptions. It also checks that a stale non-profile selection made under SDK policy ends in a terminal `TEE_MODEL_UNAVAILABLE`, with `sdkOpened = 0` and verification still "not-established", and that `approved` is empty. It passes.
- **Documentation.** README, SECURITY.md, the package README, design.md, the contract and CHANGELOG consistently describe admission of the three models. The README now says "A single Hopper or Blackwell GPU must report SPT", which closes the remaining F7 README item. `docs/reviews/pi-tee-multimodel-snp-tls-opus-review.md` matched this report through the re-review section. This enablement section still needs to be copied there.

### `ecc5cd0` and `6ea1329` (TLS and probing)

| Change | Assessment |
| --- | --- |
| Received-bytes cap: `MAX_ENCRYPTED_RESPONSE_BYTES + 1 MiB`, counted on every runtime; Bun no longer pauses (`CAN_PAUSE = !process.versions.bun`) | **Closes the F4 residual.** With a Node peer flooding a stalled reader, Bun now stops the peer at 37–39 MiB and the stream fails with `TEE_RESPONSE_REJECTED` (4/4 runs, client RSS ≤ 43 MiB). Node still pauses at 3–4 MiB. The cap counts chunk framing too, so a response within about 3% of the existing 32 MiB encrypted limit can fail slightly earlier. That is roughly 100k streamed tokens, so negligible (Info). |
| Stalled-consumer test now waits for the peer's writes to settle (`6ea1329`) | **Stable.** Bun 0/12 and Node 0/6 in isolation; the full file passes under `bun test` (4/4). |
| Probe concurrency 16; stop after 8 reachable hosts | **Correct and bounded.** Abort and empty inputs resolve; nothing is authorized by reachability. Info: the 8 hosts are the first reachable ones in delivery order and are shuffled afterwards, so delivery chooses which 8 are eligible. It already controls availability. The array returned to the caller can still receive pushes from probes in flight. That is harmless, because the candidate slice is taken once, but returning a copy would be cleaner. |
| Assumption names AMD-SB-3019/3020/3027 | Closes the earlier Info item. |

### Regression checks at `94b43a7`

- Build and typecheck are clean. `npm test` reports 87 pass, 0 fail, 3 skipped (private fixtures).
- `go test` and `go vet` pass.
- `public-build-chain.test.ts` passes with the private TDX evidence.
- The helper WASM pin is unchanged (`7877fe36…`, reproduced in the re-review).
- My hostile-peer probes still fail closed on Node and Bun: invalid name, bare LF, NUL, space before colon, close-delimited body and truncated chunk. A well-formed response passes.
- Against a Node peer capped at TLS 1.2, Node fails the handshake and Bun is rejected by the protocol check (`TEE_TLS_KEY_REJECTED`). TLS 1.3 passes on both.

## Delta review: `d0bd843` and the rebased enablement commit

This section covers [`d0bd843`](https://github.com/ariofrio/pi-tee/commit/d0bd8430c9c3159c3031eafcbbb5bc87554ff0cc) on main ("Keep verified GitHub metadata across Pi processes") and the rebased enablement commit on local `ariofrio/enable-public-builds`.

**Which commit is the branch tip.** The branch tip is now `e6cb1b7`, not the `dbbec6f` named in the request.
- `dbbec6f`'s enablement patch is identical to `94b43a7` apart from rebase context lines. It does **not** contain the report copy.
- `e6cb1b7` is `dbbec6f` plus `docs/reviews/pi-tee-multimodel-snp-tls-opus-review.md`, which is byte-identical to this report through the Enablement review.
- Merge `e6cb1b7`.

### Verdict: enable

Nothing in `d0bd843` widens what is accepted. The conditions from the Enablement review still apply: review A's sign-off on the post-`ad71a91` NVIDIA verifier commits, and the production live suite on the merged commit.

### `d0bd843`

| Change | Assessment |
| --- | --- |
| Persistent cache for two GitHub API lookups (`persistable` = `api.github.com`, `immutable` only), in `$XDG_CACHE_HOME`, falling back to `~/.cache`, under `pi-tee/github-metadata`; key = SHA-256 of the URL | **Does not widen acceptance.** The cached lookups are the cvmimage attestation list and the release commit's parents. Both URLs are content-addressed: by manifest digest and by commit SHA. Every attestation bundle is still Sigstore-verified by `--cvm-build` against the cvmimage release workflow and the manifest digest, so stale or planted bundles can only cause rejection. The parents lookup feeds only the public-source linkage check (`publicSourceParentMatched`), which has no authority of its own: the image is authorized by the signed release. Nothing from CPU, GPU, freshness, keys or helper verdicts is persisted. |
| Write only after the whole artifact chain verifies; write a temp file (`0600`), then rename into a `0700` directory | **Correct.** Rename is atomic, failures are best effort, and only fetched bytes are written, never bytes already read from disk. |
| Any failing chain that read a persisted entry deletes the whole directory, and the in-memory cache is cleared | **Correct.** The test poisons both entries, sees `TEE_PUBLIC_BUILD_REJECTED`, sees the directory emptied, and then recovers with two fresh GitHub requests. `rm` targets only `<cache>/pi-tee/github-metadata`. |
| Delivery failures (fetch errors, non-2xx other than the attestation 404, 403 rate limit) → `TEE_PUBLIC_ARTIFACT_UNAVAILABLE`; attestation 404 → `TEE_CVM_BUILD_REJECTED`; the new code is terminal and reported after a verification rejection | **Correct and fail-closed.** Only that one code passes through the outer `catch`; every other error still maps to `TEE_PUBLIC_BUILD_REJECTED`. Selection prefers a real rejection to unavailability. A terminal code only stops Pi's own retries. |
| `live-pi.ts` asks for medium reasoning effort | Harness only; no security effect. |

**Low (hardening, not blocking).** The disk path trusts the directory's contents and permissions without checking them:
- `mkdir(..., { mode: 0o700 })` does not tighten a directory that already exists.
- `readFile` does not check the owner or mode.
- The temp name `<path>.<pid>.tmp` is predictable, and `writeFile` follows symlinks.

This matters only if the cache directory is writable by someone else, for example `XDG_CACHE_HOME` pointed at a shared location. In that case a co-tenant could:
- make the source-linkage audit check pass for a release where it would not, or
- force rejections, or
- have the extension overwrite a file through a symlink.

It could not get unverified attestation content accepted. The local machine is inside the declared trust boundary, so this is hardening. Suggested fix:
- `lstat` the directory and ignore the cache unless it is owned by the current uid with mode `0700`;
- create temp files with `flag: "wx"`;
- ignore a relative `XDG_CACHE_HOME`, as the XDG spec requires.

**Info.** The new test leaves its `.scratch/work/github-metadata-*` directory behind.

### Checks at `dbbec6f` (code identical to `e6cb1b7`)

- Build and typecheck are clean.
- `npm test`: 87 pass, 0 fail, 3 skipped.
- `public-build-chain.test.ts` passes with the private TDX evidence, including the persistence, poisoning-wipe, 404 and outage cases.
- Persisted files were `0600` in a `0700` directory.

## Post-merge delta: `7b8ee9f` and `5fbe387`

This section reviews [`5fbe387`](https://github.com/ariofrio/pi-tee/commit/5fbe38721c9b1f70cda382bb5d5fdbb86feb2071) ("Persist each GitHub metadata lookup after its own check"), which is on `origin/main` after the merged enablement [`37e3b5e`](https://github.com/ariofrio/pi-tee/commit/37e3b5e0cb9fb0696eafc512e431730c364644eb). It also covers [`7b8ee9f`](https://github.com/ariofrio/pi-tee/commit/7b8ee9f) ("Trust the GitHub metadata cache only in a private directory"), which landed between the review of `e6cb1b7` and the merge.

### Verdict: OK

Neither commit widens what is accepted.

### `7b8ee9f` resolves the Low hardening item from the delta review

- **Directory check.** `privateDirectory` calls `lstat` on the cache directory itself, so a symlinked directory fails `isDirectory()`. It requires `mode & 0o077 === 0` and the current uid. It runs before every read and again after `mkdir` before every write.
- **Temp files.** Temp names are random (`randomBytes(8)`), created with `flag: "wx"` and mode `0600`, then renamed into place.
- **`XDG_CACHE_HOME`.** A relative value is ignored.
- **Residual (Info).** Ancestor directories are not checked. That leaves a check-then-use window only if an ancestor of the cache directory is writable by another user.

### `5fbe387`: per-entry persistence

| Behavior | Assessment |
| --- | --- |
| The attestation list is persisted only after `--cvm-build` verifies a bundle from it for this manifest digest and tag. The commit lookup is persisted only after its single parent equals the signed provenance's `sourceCommit`. | **Correct.** The trigger is the check that consumes each lookup. Both URLs are content-addressed (manifest digest; release commit), so a passed check stays valid for that key regardless of later, unrelated failures. |
| A stored entry is removed only when its own check fails. Entries fetched fresh that fail are never written. | **Correct.** Removal is limited to entries actually read from disk (`persistedReads.has(url)`). A poisoned list or parents entry is rejected and dropped, and a refetch recovers. |
| Unrelated failures (registry outage, later chain or GPU rejection) keep verified entries | **Intended, and harmless.** Every later use re-runs the same checks: bundles are Sigstore-verified each time, and helper results are cached in memory only. |
| Side effect | Info: an abort or helper failure inside a check also removes an otherwise valid stored entry. That costs only a refetch. |
| Nothing else changed | Error mapping, the 404 rejection, and the CPU/GPU/freshness/key paths are untouched. No new persisted data types. |

### Checks at `5fbe387`

- Build and typecheck are clean.
- `npm test`: 87 pass, 0 fail, 3 skipped.
- `public-build-chain.test.ts` passes with the private TDX evidence, including:
  - an unrelated GHCR outage keeps both entries;
  - each poisoned entry alone is rejected and only that entry is dropped;
  - recovery refetches exactly the dropped URL.

Written by Claude
