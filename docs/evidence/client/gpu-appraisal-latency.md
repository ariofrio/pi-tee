# GPU appraisal latency

**Observations: 2026-10-10 UTC.** Main at [ebea617](https://github.com/ariofrio/pi-tee/commit/ebea617), compared with ebea617 plus three client changes: the reference-manifest cache in `nvidiaCollateralBridge()` ([nvattest-bridge.ts](../../../packages/core/src/nvattest-bridge.ts)), one verifier per GPU with at most eight at once in `runNvidiaVerifier()` ([nvidia-verifier.ts](../../../packages/core/src/nvidia-verifier.ts)), and GPU verification started alongside the build check in `appraiseWorker()` ([worker-appraisal.ts](../../../packages/tinfoil/src/worker-appraisal.ts)). Locked dependencies, Node 26.10.0 on macOS arm64 over a residential network. Credential-free: no inference, no NRAS.

## Scope

- Tinfoil GLM-5.3 public worker `glm-5-3-inf17` (eight GB110 GPUs, Blackwell MPT), appraised under `public-builds,egress=metadata`.
- Every run used a fresh nonce except the verifier-only runs, which re-appraised one saved eight-GPU sample against NVIDIA's live reference and OCSP services. That sample stays outside the repository.
- One worker and one client machine. Latency depends on the network path to NVIDIA and Tinfoil, so the absolute figures are not a promise.

## Evidence

On main, NVIDIA's verifier made 88 collateral requests for eight GPUs, one at a time with a median of about 60 ms each. 16 of them fetched the same two reference manifests, and the 72 OCSP requests covered 14 distinct certificates. Each OCSP response was produced for its request and echoed its nonce, with a next update 24 hours later.

Verifier only, on the saved sample. Times are for warm runs 2–4 of each process, over three interleaved rounds:

| Concurrent verifiers | Time | Peak RSS |
| --- | --- | --- |
| main (one verifier for all GPUs) | 7.1–9.9 s | 264–306 MB |
| 1 | 8.1–9.4 s | 275–323 MB |
| 2 | 3.7–4.5 s | 339–377 MB |
| 3 | 2.9–3.6 s | 372–478 MB |
| 4 | 2.0–2.7 s | 463–474 MB |
| 6 | 1.8–2.8 s | 549–628 MB |
| 8 | 1.0–1.8 s | 564–779 MB |

Complete appraisal of fresh evidence, with the first run in a new process and then three more, over two rounds. Every run rated H1/G1:

| Client | First run | Later runs | Peak RSS |
| --- | --- | --- | --- |
| main | 14.0–14.4 s | 8.0–9.3 s | 441–463 MB |
| with the three changes | 5.2 s | 1.6–2.0 s | 665–667 MB |

In earlier prototype runs at the same worker, evidence retrieval took 0.55–0.75 s and the eight-GPU verifier window about 0.65 s of a warm 1.4–2.1 s appraisal. A cold public-build check took 2.6–3 s, which now overlaps GPU verification.

## Limits

These figures cover appraisal latency, not inference or availability. Reusing manifests saves their downloads only. Every run still verifies manifest signatures and sends fresh nonce-bearing OCSP requests. OCSP responses and appraisal verdicts are not cached.

Written by Claude.
