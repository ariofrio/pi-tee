# Security contract

The default policy is `public-builds`: named public source/release/build authorities may authorize updates automatically, while hardware, key-custody, serving-path and runtime requirements remain mandatory. No complete inference profile is enabled yet. `sdk` explicitly accepts the experimental route's disclosed authorities; `approved` retains optional independent frozen-workload semantics, with no implemented profile. Current provider reports mark `publicBuildVerification`, `independentApproval`, `closedTrustSet`, and `protectedSession` as `not-established`. The repository lockfile freezes tested dependency artifacts; fresh tarball installs can resolve SDK transitive ranges differently. Package-load smokes do not qualify that new verifier set.

The [automatic public-release/CPU verifier](tools/tinfoil-public-build/README.md) authenticates dynamic Tinfoil measurements and freshness without deployment pins. It is evidence-only research tooling, not inference admission. A production profile must be reviewed as a full serving-path contract. Public-release provenance is not an independent rebuild or a provider-supplied “verified” boolean.

## Required closed inventory

A production profile must name its authorities, authenticated artifacts/keys and explicit update processes for:

1. Local Pi, runtime, extension, verifier/helper, and their complete dependency artifacts; local plaintext-accessing extensions, hooks, and tools.
2. The selected AMD/Intel attestation roots, CPU generation, security-version floors, debug/migration rules, collateral validity and revocation process.
3. NVIDIA trust roots/verdict keys, firmware/reference policy, confidential-computing mode, actual device/topology and secure CPU–GPU/fabric channels.
4. Exact provenance roots and GitHub issuer/repository/workflow/build identities. Public-build mode names ongoing software publishers; authenticated per-request commit/digest values need not be hardcoded. Frozen mode additionally names an independent approval authority.
5. Every guest firmware/OS/container/configuration/model/tokenizer/remote-code input. Approved measured code must verify downloaded bytes before use.
6. All plaintext/key-capable processes and sidecars, egress, persistent caches, deployment/configuration writers, token holders and runtime environment overrides.
7. Generation, export, provisioning, persistence, migration and destruction of TLS/HPKE/signing/OHTTP/cache keys; every authority capable of admitting another recipient.
8. Any KMS, chain/MPC/contract governance, freshness process, remote appraisal policy, or WebPKI key bootstrap whose honesty affects the claim.

Delivery endpoints can leave the trusted set only after authentication and freshness/revocation policy remove their ability to authorize software, references, keys or recipients. Public-build mode trusts the named publishers and hosted build processes, including provider-owned ones; it does not claim manufacturer-only trust. The current probe accepts matching signed freshness witnesses for seven days, with five minutes of future skew. That is bounded stale endorsement, not immediate revocation or a newest-release rule. Availability and metadata leakage remain separate properties. Neither transparency nor a delayed update is independent approval.

## Provider-specific blockers

For Tinfoil, verify a reachable worker's CPU platform and custody, AMD revocation/security floors or authenticated TDX hardware references, exact authorized guest/model bytes, and actual GPU/fabric protection. A decrypting router needs an enforced per-request backend policy, including conditional sidecars and unapproved-fallback prevention. The stock JS SDK's automatic rotation recovery has no pre-send independent approval callback. [SDK recovery](https://github.com/tinfoilsh/tinfoil-js/blob/eac102f50ad3c1bfc3fd3cefe8a615671d86fa52/packages/tinfoil/src/secure-client.ts#L370), [Go reference selection](https://github.com/tinfoilsh/tinfoil-go/blob/05e817920780362d6c79b0035902d51bd608918b/verifier/client/client.go#L264).

For NEAR, establish a serving-session binding beyond shared TLS/model keys; appraise authenticated MRTD and RTMR0–2 in addition to the SDK's exposed measurements; secure key-release and runtime-mutation behavior; verify runtime package/model bytes; and establish the actual CPU–GPU/forwarding path. A proposed TLS-exporter quote must bind an exporter computed by the measured terminator from its actual connection, not a caller-supplied value. Current deployment facts and mechanisms must be demonstrated. [Intel adapter](https://github.com/nearai/inference-sdk/blob/b9930893a9f560e66898e1616111c5ac2241686c/js/src/utils/intel.ts#L101), [runtime recipe](https://github.com/nearai/cvm-compose-files/blob/cda2032fa8f8638639d858703b6de4d76c2118e8/prod/dsv4-qwen36-gemma4.yaml#L254), [shared signer contract](https://docs.near.ai/cloud/verification/cloud-api/model-attestations).

For protected sessions, implement and test a fail-closed guard after physical routing, before serialization, across retries, model switches, fallback, compaction, summaries, and background requests. Pi request-hook exceptions are caught and logged, so throwing from that hook is insufficient. [Hook implementation](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/core/extensions/runner.ts#L1361).

## Sensitive data

Ordinary reports contain status and static trust assumptions, not prompts, tokens, responses, or complete evidence. NEAR buffering is memory-only and bounded. Tinfoil uses a fresh memory-only cache secret for each request client, avoiding the SDK's default cache-secret file. Credentials are managed by Pi. No automatic evidence upload or background title/summarization integration is added.

Discovery metadata, usage and prices are untrusted provider claims. Model output correctness, availability, truthful billing, traffic-analysis resistance, undocumented side-channel/physical protection and local-machine compromise are outside the claim. Authenticated SDK evidence alone does not enable production public-build or independently approved workloads.

NEAR's TEE-only discovery filter uses public capability claims, not security evidence. Showing all models changes visibility only. Unsupported or unknown models are rejected before SDK setup; declared capability still requires fresh SDK evidence and a model-signed response. Neither the filter nor its override enables Approved workloads.
