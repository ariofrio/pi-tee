# Offline Tinfoil CPU candidate appraisal

This helper verifies public v3 CPU evidence against locally embedded candidate values. It is research tooling, outside the npm extensions. It never enables Approved inference, returns inference keys, or sends credentials/prompts. A successful result is only CPU appraisal; GPU, channels, workload approval and protected Pi sessions remain separate gates.

`main.go` calls `envelope.Check`, `quote.Authenticate`, `quote.Assemble` and `Validate` from exact [Go verifier revision 23734b7](https://github.com/tinfoilsh/tinfoil-go/tree/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier). Manufacturer collateral travels inside the document; verification uses pinned vendor roots, revocation and local clock checks with no runtime network. It does not call provider provenance, platform-endorsement or freshness-witness verification. The caller must generate and retain its own unpredictable nonce; an evidence file alone proves no new live session.

The CLI accepts bounded JSON `{ "nonce": "64 lowercase hex characters", "envelope": { ... } }` on stdin. It reports bounded metadata/failure codes on stdout and exits nonzero on rejection. No caller-supplied policy or relaxation is accepted. The wrapper rejects unknown fields and trailing JSON; the v3 envelope parser additionally rejects duplicate/unknown envelope members. Machine identity is used only after manufacturer authentication. Any matching manufacturer-authenticated machine may be considered; operator identity is not an authorization root.

## Local pins and trust

[The AMD candidate](candidate.json) permits only CPUID `0x00A10F11`, the exact Gemma SNP launch measurement, non-debug/non-migratable VMPL0, required platform bits and fixed floors. Its firmware floor is decimal `1.55.49`, SNP SVN `27` (`0x1B`), microcode SVN `86` (`0x56`), and both launch/current mitigation bits 0–2. Bootloader SVN10 is retained from authenticated evidence. These are necessary candidate conditions, not a complete assertion that every known vulnerability is mitigated.

Sources: [AMD-SB-3014](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3014.html), [AMD-SB-3016](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3016.html), [AMD-SB-3020](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3020.html), [AMD-SB-3023](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3023.html), [AMD-SB-3027](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3027.html). Mitigation vectors are checked as sets of bits by the pinned vendor library. The sampled AMD worker has firmware `1.55.40`, SNP SVN23, microcode SVN84 and mitigation vectors `0`; the local CLI rejects it despite SDK acceptance. Some AMD mitigations have no attested TCB value; [AMD-SB-3034](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3034.html) removed those values on September 24, 2026. A passing floor must not be mistaken for complete host-firmware qualification.

[The Intel candidate](tdx.json) freezes MRTD, RTMR0, Gemma workload registers, zero RTMR3, MRSEAM, TD attributes, XFAM and a single permitted VM shape. Intel QE/module/platform status must be `UpToDate`; signatures, revocation and validity are checked. The signed collateral edition floor `20` matches the minimum authenticated edition in the sampled document. [Status enforcement](https://github.com/google/go-tdx-guest/blob/v0.3.1/verify/verify.go#L928), [policy assembly](https://github.com/tinfoilsh/tinfoil-go/blob/23734b7c6b9acf5359087412b03ebb524c2fb2f1/verifier/quote/tdx/expectations.go).

The initial TDX boot/security values came from authenticated `tinfoilsh/platform-endorsements` `v0.0.16`, digest `0cba58535ac96b734d02f9ebd5db6e90f51c193e9d27c4432c8fc5a363f83d64`, restricted to the observed boot profile and shape. The source/build derivation still needs independent approval. Future provider releases cannot change these files at runtime. The Gemma workload is the fixed `v0.0.25` artifact described in [the direct assessment](../../docs/direct-access.md).

For this CPU-only check, runtime authorization trusts this repository's local candidate-selection process, the fixed helper/dependency bytes in [go.mod](go.mod)/[go.sum](go.sum), the Go compiler/runtime, the local OS/clock, and the selected AMD or Intel hardware, firmware, endorsement/revocation/collateral-signing processes. The pinned Tinfoil verifier code is trusted software, not a remotely selected provider release authority. Bootstrap still used GitHub/Sigstore/Tinfoil build/reference processes and WebPKI to acquire and authenticate candidates. Those values have not received an independent source/build audit. Removing their ongoing policy authority does not retroactively establish independent approval.

## Build and reproduce

Use Go 1.26.6 in the locked repository. The standalone module does not change npm dependencies or extension defaults.

```sh
mkdir -p .scratch/work
GOTOOLCHAIN=go1.26.6 go -C tools/tinfoil-cpu build -mod=readonly -trimpath -buildvcs=false -o ../../.scratch/work/tinfoil-cpu-verifier .
node scripts/research/tinfoil-cpu.mjs intel .scratch/work/intel-evidence.json
# Expected nonzero rejection for the underpatched AMD worker:
node scripts/research/tinfoil-cpu.mjs amd .scratch/work/amd-evidence.json
PI_TEE_CPU_TEST_EVIDENCE=../../.scratch/work/amd-evidence.json \
PI_TEE_TDX_TEST_EVIDENCE=../../.scratch/work/intel-evidence.json \
go -C tools/tinfoil-cpu test -mod=readonly -v ./...
go -C tools/tinfoil-cpu vet -mod=readonly ./...
```

The probes use Node 24, send no inference, pass no environment credentials to the helper, impose response/process deadlines and body/output limits, and optionally create owner-only evidence fixtures without overwriting existing files. Worker availability is mutable; an unexpected result should be investigated without changing pins to match it.

The opt-in real-evidence tests use actual CPU cryptography. They remove all provider reference/freshness collateral, reject replay nonces and wrong workload/boot pins, and mutate keys/GPU evidence while recomputing every untrusted envelope hash and REPORT_DATA field. The untouched signed CPU report must reject those well-formed substitutions. A test-only weaker AMD policy supplies a positive control for the authentic older quote; the CLI cannot select it. Default tests skip these live-fixture cases when their explicit paths are absent.

Written by Codex.
