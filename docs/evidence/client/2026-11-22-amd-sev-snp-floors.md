# AMD SEV-SNP floors for AMD-SB-3059 and AMD-SB-3061, 2026-11-22

On 2026-11-10 AMD published [AMD-SB-3059](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3059.html) (CVE-2026-0462: a malicious hypervisor can redirect MMIO accesses, breaking SEV-SNP guest memory integrity) and [AMD-SB-3061](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3061.html) (CVE-2026-40671: VMRUN error handling can expose SEV-SNP guest register state through a transient-scheduler side channel). This branch raises pi-tee's per-CPU SEV-SNP floors to those fixes. Live evidence was collected 2026-11-22 11:56–12:10 UTC from macOS, using Node 26.10 and Go 1.26.6, with client [c1418ff](https://github.com/ariofrio/pi-tee/commit/c1418ff) and this branch. No inference was sent.

## AMD's published values

Bulletin text was read on 2026-11-22. Both bulletins are at their initial 2026-11-10 revision.

| Bulletin | Genoa (EPYC 9004) | Turin (EPYC 9005) |
| --- | --- | --- |
| AMD-SB-3059 | SEV FW `1.3A.4`, mitigation bit 6, `TCB[SNP]=0x1E` | SEV FW `1.3A.0A`, mitigation bit 12, `TCB[SNP]=0x8` |
| AMD-SB-3061 | Microcode: B1 `0x0A10115B`, B2 `0x0A10125B` | Microcode: Classic C1 `0x0B002176` |

- **Dates.** AMD released both bulletins' firmware and microcode on 2026-08-12. PI firmware is planned for Dec'26 (SB-3059) and Nov'26 (SB-3061).
- **No TCB value in SB-3061.** It gives no microcode TCB value. [AMD-SB-3027](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3027.html) pairs each microcode revision with the `TCB[MICROCODE]` it reports: Genoa `0x0A101156` → `56`, Genoa-X `0x0A101251` → `51`, Bergamo `0x0AA0021B` → `1B`, Turin C1 `0x0B002151` → `51`, Turin Dense `0x0B10104E` → `4E`, Milan `0x0A0011DE` → `DE` and Milan-X `0x0A001247` → `47`.
- **Firmware versions.** [AMD-SB-3020](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3020.html) lists Genoa SEV FW `1.37.31` at SPL `0x1B` and Turin `1.37.41` at SPL `0x04`.
- **Other SPLs.** Neither new bulletin lists a bootloader, TEE or FMC SPL.

## Floors

| CPUID | Previous build / ABI, TCB | New build / ABI, TCB |
| --- | --- | --- |
| `19/11/01` Genoa B1 | 21 / 1.55, BL `07` TEE `00` SNP `1b` µcode `56` | 4 / 1.58, BL `07` TEE `00` SNP `1e` µcode `5b` |
| `19/11/02` Genoa-X B2 | 21 / 1.55, BL `07` TEE `00` SNP `1b` µcode `51` | 4 / 1.58, BL `07` TEE `00` SNP `1e` µcode `5b` |
| `1a/02/01` Turin C1 | 0 / 1.58, FMC `01` BL `01` TEE `01` SNP `04` µcode `51` | 10 / 1.58, FMC `01` BL `01` TEE `01` SNP `08` µcode `76` |

- **SNP SPL.** Copied from SB-3059.
- **Microcode SPL.** The low byte of SB-3061's revision, following SB-3027's pairing. SB-3061 itself states no TCB value.
- **Build and ABI.** AMD writes SEV firmware versions as hexadecimal ABI major, ABI minor and build. `1.3A.4` is ABI 1.58 build 4, and `1.37.31` is ABI 1.55 build 49. The router below reports exactly 1.55.49 at SPL `0x1B`, and the Coordinator reports 1.58.4 at SPL `0x1E`.
- **Why the build floor fell.** The build count restarted at ABI 1.58: Turin `1.37.41` (1.55.65) was followed by the 1.58.3 observed below. The pinned [go-sev-guest](https://github.com/tinfoilsh/go-sev-guest/blob/bec7bdb637fd/validate/validate.go#L577-L585) compares build and ABI separately, so keeping build 21 would rate SB-3059's own Genoa firmware below floor. Both fields now come from the bulletin's firmware version, and stronger publisher values are kept.
- **Unchanged.** Bootloader, TEE and FMC floors are unchanged. Mitigation vectors are not checked separately, because the SPL floors already require the bulletins' firmware.

## Live evidence

The fields below were decoded from the reports. Tinfoil's reports were authenticated by the helper against AMD's VCEK and CRL. Privatemode's SDK authenticated the Coordinator's report.

| Source | CPUID | Firmware | Current = launch TCB | Mitigation vector |
| --- | --- | --- | --- | --- |
| `inference.tinfoil.sh` router, 7 samples, one chip | `19/11/01` | 1.55.49 | BL `0a` TEE `00` SNP `1b` µcode `58` | `0xf` |
| Tinfoil `gemma4-31b-inf6-{0..3}` | `19/11/01` | 1.55.40 | BL `0a` TEE `00` SNP `17` µcode `54` | report v3, none |
| Tinfoil `glm-5-3-inf19-0`, `glm-5-3-inf22-0` | `1a/02/01` | 1.58.3 | FMC `01` BL `03` TEE `02` SNP `05` µcode `61` | `0x3f` |
| Privatemode Coordinator, CDN manifest `d63eb5cf…` | `19/11/01` | 1.58.4 | BL `0c` TEE `00` SNP `1e` µcode `58` | `0x3ff` |

- **Tinfoil sample.** Discovery listed 44 workers for four of the seven probed models; the other three had no discovery entry. 16 answered: 10 TDX workers, which these floors don't affect, and the 6 SEV-SNP workers above. The other 28 timed out on connect.
- **Mitigation bits.** Only the Coordinator sets SB-3059's Genoa bit 6. Neither Turin worker sets bit 12.
- **Tinfoil's platform policy.** Every sample carried `tinfoilsh/cvmimage` `platform-v0.1.15` (digest `77466c44…`).
  - Genoa production: ABI 1.55, build 21, BL `07` TEE `00` SNP `0e` µcode `48`.
  - Turin production: ABI 1.58, build 0, FMC `01` BL `01` TEE `01` SNP `04` µcode `52`.
- **Privatemode's manifest.** v1.64.0 requires Genoa BL 12, TEE 0, SNP 30, microcode 88 and mitigation vector 1023.

## Rating impact

Each helper result is pi-tee's helper at c1418ff and at this branch, run on the same saved evidence.

| Route / population | c1418ff | This branch |
| --- | --- | --- |
| Tinfoil `glm-5-3` Turin workers | Helper H1. Route `TEE_PUBLIC_BUILD_REJECTED` | Helper H2: rejected under `host=current`, admitted only from `host=outdated-firmware`. Route `TEE_PUBLIC_BUILD_REJECTED` |
| Tinfoil `gemma4-31b` Genoa workers | Helper H2 (already below the SB-3020 floor). Route `TEE_PUBLIC_BUILD_REJECTED` | Unchanged |
| Tinfoil direct availability | Unavailable | Unchanged |
| Tinfoil router | `TEE_PUBLIC_BUILD_REJECTED` | Unchanged |
| Privatemode `privatemode-mesh` with the logged CDN manifest | A2/H3/G3/X3. Diagnostic below floor because build 4 < 21 | A2/H3/G3/X3. Diagnostic below floor because microcode `58` < `5b` |
| NEAR, Chutes | TDX only | Unaffected |

- **Direct.** The direct route's rejections happen before any host rating, as in the [2026-11-07 release drift](../tinfoil/2026-11-07-release-drift.md). The floors change only what those workers would rate once admitted. The gateway appraises the same workers but was not run separately.
- **Router.** The router's rejection is the same under both helpers. Its firmware met the old floors and is below the new ones, so if the router were admitted, its component appraisal would be H2 instead of H1. The route stays H3 either way, and `trust-provider-and-host` still admits H2.
- **Privatemode.** Under c1418ff the diagnostic called SB-3059's own firmware below floor. Under the shipped hard pin the route is still rejected for the manifest drift recorded on [2026-11-20](../providers/2026-11-20-chutes-privatemode-drift.md).
- **Tinfoil's Genoa policy.** Tinfoil's `platform-v0.1.15` Genoa policy requires build ≥ 21 independently of ABI. A Genoa host upgraded to SB-3059's 1.58.4 firmware would fail that publisher minimum, and pi-tee would reject it under every policy, until Tinfoil revises its policy or AMD's build count reaches 21. pi-tee does not lower publisher minima. This follows from the signed policy alone; no such Tinfoil host was sampled.

## Helper build

`npm run build:wasm -- --go-only` produced an uncompressed `tinfoil-public-build.wasm` with SHA-256 `c43ee86d62cc3ea38fd5b8759588637bc5338cd4c38847ac4dd70e753dcc856d` in each of two separate build directories. The committed gzip has SHA-256 `dd045fdf464c0eba17b5bab93e200dd1343616ba2e9cc147894069490a886999`. The same toolchain rebuilt c1418ff's pin, `d9efbbae0f1163c4f931b022764ae69e51b81f0f2d3ce6b3577a673ba5f22dd2`, exactly. The [WebAssembly verifier workflow](../../../.github/workflows/wasm-verifiers.yml) has not yet rebuilt this branch.

## Not established

- **Microcode SPL.** No AMD source states the SPL for SB-3061's revisions. The values rely on SB-3027's pairing.
- **Genoa-X.** No `19/11/02` host was sampled. Its floor follows SB-3061's "Genoa RS-B2" revision.
- **Turin build 10.** It comes from the bulletin's version string alone; no patched Turin host was observed.

Raw evidence is kept privately. No credential, token, prompt or response is recorded here. Privatemode received only the attestation and secret-exchange requests. NRAS was not contacted, though NVIDIA's collateral services may have received requests from the local GPU verifier during worker appraisal.
