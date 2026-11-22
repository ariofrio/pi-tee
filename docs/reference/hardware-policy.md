# Hardware policy

These are client-enforced floors, checked against authenticated evidence. A signature proves authenticity, not that a firmware version meets the local policy. Code is authoritative; update this reference when floors change and requalify affected routes.

## Intel TDX

H1 requires `UpToDate`, a 16-byte SVN whose first components are at least `[3,1,2]` (remaining floor bytes zero), and both authenticated platform TCB/QE collateral evaluation editions at least 20. [TDX_SVN_FLOOR, TDX_COLLATERAL_FLOOR, rateAuthenticatedTdxHost()](../../packages/core/src/tdx-host.ts).

NEAR and Chutes can rate supported fresh `OutOfDate`, below-floor or unreadable-floor evidence H2. That never relaxes signature, freshness or key binding. Tinfoil's pinned Go verifier rejects Intel `OutOfDate` under every policy before rating; a permissive H threshold cannot make that path available.

## AMD SEV-SNP

TCB components below use hexadecimal values; build and ABI are decimal. Both current and launch TCB must meet the local minima for H1, alongside publisher/manufacturer checks.

| CPUID family/model/stepping | Minimum firmware build / ABI | Minimum TCB |
| --- | --- | --- |
| `19/11/01` Genoa | 4 / 1.58 | bootloader `07`, TEE `00`, SNP `1e`, microcode `5b` |
| `19/11/02` Genoa-X | 4 / 1.58 | bootloader `07`, TEE `00`, SNP `1e`, microcode `5b` |
| `1a/02/01` Turin | 10 / 1.58 | FMC `01`, bootloader `01`, TEE `01`, SNP `08`, microcode `76` |

SNP and microcode minima are those of [AMD-SB-3059](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3059.html) and [AMD-SB-3061](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3061.html) (2026-11-10). The microcode SPL is the low byte of AMD's microcode revision, the pairing [AMD-SB-3027](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3027.html) publishes. Build and ABI are checked separately, so both come from the bulletin's SEV firmware version (Genoa `1.3A.4`, Turin `1.3A.0A`): AMD restarted the build count at ABI 1.58. A publisher minimum that is stronger in either field still applies. [Floor record](../evidence/client/2026-11-22-amd-sev-snp-floors.md).

[Go CPU enforcement](../../tools/tinfoil-public-build/main.go), [shared SNP diagnostics](../../packages/core/src/cpu-floors.ts). Tinfoil SEV-SNP H2 retains publisher-signed minima, AMD signatures/CRL, nonce/endpoint binding and a non-debug, non-migratable VMPL0 production guest with non-provisional firmware. The pinned SNP OVMF identity belongs to the [serving contract](../contracts/tinfoil-public-builds.md). Privatemode Coordinator diagnostics do not establish serving-worker freshness or raise the route above H3.

## NVIDIA GPUs

For G1, every serving device must authenticate with fresh nonce-matching signed evidence, good certificate/reference revocation, secure boot, debug disabled, distinct identity, complete serving count and CPU-hashed evidence.

| Hardware model | GPUs | G1 mode | Minimum driver / VBIOS |
| --- | --- | --- | --- |
| `GH100 A01 GSP BROM` | 1 | SPT | `595.71.05` / `96.00.D0.00.03` |
| `GB100 A01 GSP BROM` | 1–8 | SPT for one; MPT for several | `595.71.05` / `97.00.D9.00.35` |
| `GB110 A01 GSP BROM` | 1–8 | SPT for one; MPT for several | `595.71.05` / `97.10.64.00.0C` |

[GPU_POLICIES / checkGpuAppraisal() / rateGpuAppraisal()](../../packages/core/src/gpu-appraisal.ts) apply the same rules to local and NRAS verdicts. Authenticated unrevoked below-floor firmware, nonce-only association and Hopper PPCIe with unattested NVSwitches are G2 gaps; incomplete serving coverage is G3. NEAR/Chutes/Privatemode cannot raise G3 using provider-assembled lists or successful individual checks.

Floors are the oldest signed, unrevoked versions seen at qualification, not a total security ranking or a promise that all newer versions are safe. Reference matching and revocation still apply. Worker-selected still-valid collateral can lag a new revocation until expiry; the [Tinfoil contract](../contracts/tinfoil-public-builds.md#client-session-and-limits) records the observed validity limits.
