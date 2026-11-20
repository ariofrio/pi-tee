# Chutes and Privatemode deployment drift, 2026-11-20

Observed 2026-11-20 22:13–22:40 UTC from macOS on Node 26.10, client [64e86da](https://github.com/ariofrio/pi-tee/commit/64e86da) and this branch, policy `trust-provider-and-host`. Chutes rejected `moonshotai/Kimi-K3-TEE`, which had passed on 2026-11-07, and `Qwen/Qwen3.5-27B-TEE`. Privatemode rejected `glm-5.3`. Both routes reported `TEE_ATTESTATION_REJECTED`. Both were deployment changes. Neither was caused by expiring collateral.

## Observations

| Route at 64e86da | Reported | Check that failed | Evidence presented |
| --- | --- | --- | --- |
| `chutes-e2ee` | `TEE_ATTESTATION_REJECTED` | [`verifyChutesInstance()`](../../../packages/chutes/src/evidence.ts) compares the signed body's `evidence.tdx_quote` with the appraised quote | The body is signed under the quote-bound SPKI and contains `{ evidence: { quote, nvtrust_evidence }, nonce }`. Its `quote` equals the appraised quote byte for byte, but it has no `tdx_quote`. All 8 sampled instances (6 Kimi, 2 Qwen) passed every other check: Intel `UpToDate`, TD attributes, nonce/key/SPKI report data, envelope signature, GPU list and H1 floors |
| `privatemode-mesh` | `TEE_ATTESTATION_REJECTED` | The worker's manifest check on the attestation response (`TEE_WORKLOAD_PIN_REJECTED`, lost when the worker's failure reached the transport) | The Coordinator's single manifest has SHA-256 `d63eb5cf91cb3079fe25a848573a4d0e9d869f462dab4f71fd02bdb372f8e833`, not the shipped v1.58.0 pin `384a2137…`. Only `/privatemode/v1/attest` was requested; no secret exchange |

- Chutes' guest attestation service renamed the signed field from `tdx_quote` to `quote` in [sek8s v1.5.0](https://github.com/chutesai/sek8s/commit/a526aef429) (released 2026-10-11). Its model now says `quote` carries a TDX quote or an SEV-SNP report on every platform. The fleet adopted it between the 2026-11-07 pass and this observation.
- Privatemode's live Coordinator manifest is byte-identical to [the CDN manifest](https://cdn.confidential.cloud/privatemode/v2/manifest.json), which was last modified `Sat, 14 Nov 2026 16:16:43 GMT`. Privatemode [v1.64.0](https://github.com/edgelesssys/privatemode-public/releases/tag/v1.64.0) was published about 20 minutes later. Compared with v1.58.0, all 8 policies are new: the namespace changed from `continuum-0a7a47` to `continuum-13d78c` and the `*` SAN was dropped. The SNP launch measurement, the TDX MRTD and RTMRs 1–2, and the seedshare owner key also changed. SNP minimums were raised (SNP firmware 28 → 30, mitigation vector 15 → 1023).

## Time-dependent inputs

The failures did not depend on the clock:

- **Embedded roots, all valid until at least 2045.** The Intel SGX Root CA used by `@phala/dcap-qvl` and by the Privatemode SDK runs to 2049-12-31. The SDK's AMD ARK/ASK roots for Milan, Genoa and Turin run to 2045–2048. The Sigstore trusted root's current Fulcio, Rekor, CT and TSA entries have no end date.
- **Fetched collateral, current.** Intel TDX TCB info and QE identity were issued 2026-11-20 at evaluation-data number 20, valid until 2026-12-20.
- **Fake clocks.** The same Chutes evidence and collateral, appraised at 2026-11-07, fail with `TCBInfo issue date is in the future`. At 2026-12-21 they fail with `TCBInfo expired`. At the observation time, quote verification passes and only the signed-field check fails.

## After the fixes

- **Chutes.** The signed body may bind the appraised quote under `quote` or the earlier `tdx_quote`. Exactly one must be present, and it must equal the appraised quote. Nothing else changed. Both models were admitted at A3/H1/G3/X3. The capped Pi suite passed on Kimi-K3: completion, usage, stored-key precedence, Unicode tool follow-up, reasoning and RPC cancellation. On Qwen3.5-27B, completion, usage and tool follow-up passed twice. Its reasoning step used up the harness's 2048-token reasoning cap while still thinking (`stopReason: length`), so no final answer was returned.
- **Privatemode.** A mismatched manifest or policy closure now reports `TEE_WORKLOAD_PIN_REJECTED`, and an unsupported platform reports `TEE_CPU_POLICY_REJECTED`. These are pi-tee's own checks on the presented document. SDK errors are still discarded. The route stays rejected under the default hard pin. Adopting v1.64.0 would approve new software measurements, a new seedshare owner key and new policies, so it is left to the pin holder. With `PI_PRIVATEMODE_MANIFEST_PATH` set to the captured v1.64.0 bytes, the same client reached A2/H3/G3/X3 with no inference sent. The Coordinator reported SNP build 4, below the Genoa diagnostic floor of 21.

Raw evidence, collateral and the captured manifest are kept privately. No credential, invocation token, prompt or response is recorded here, and NRAS was not contacted.
