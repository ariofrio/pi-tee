<a id="confidential-inference-providers-vs-the-pi-tee-security-model"></a>

# Confidential-inference ecosystem survey

**Evidence window: 2026-10-08–09; reconciled against merged pi-tee main fa5e154.** This is the canonical ecosystem comparison using the [security model](security-model.md). It combines preserved source investigations and scoped later adapter records; no new live probe or remote product review was performed for this restructuring. Installed behavior lives in the [provider guide](providers.md).

The [original survey](evidence/providers/2026-10-08-survey.md) retains its R1–R8 bar, every verdict, provider source link and rule-out. The [anonymous verification](evidence/providers/2026-10-09-anonymous-verification.md) retains pinned sources, bindings and unresolved cells. † means conservative unresolved evidence, not an observed regression. All levels concern the specified path, never an entire vendor/fleet.

## Implemented adapters

| Adapter | Scope and result | Evidence |
| --- | --- | --- |
| Tinfoil public direct / billing relay | Conditional A1/H1/G1/X2/B3/S3 baseline; weaker authenticated hardware levels require admitting thresholds. No claim all workers pass | [Serving contract](contracts/tinfoil-public-builds.md), [client qualification](evidence/client/implementation-validation.md#security-model-validation), [gateway qualification](evidence/tinfoil/gateway-validation.md#validation) |
| NEAR direct / SDK gateway | A3/G3/X3; H1/H2 per fresh checked recipient. Shared custody and runtime deployment remain provider-controlled | [Source/KMS investigation](evidence/nearai/runtime-key-custody.md), [credentialed multi-model discovery](near-direct-discovery.md#live-validation-2026-10-09) |
| Chutes instance-key route | A3/G3/X3; fresh H1/H2 once credentialed key discovery allows nonce/key commitment verification. No complete serving-GPU/software closure | [Credentialed validation and retained rejected rows](chutes-validation.md), [per-runtime sanitized receipts](validation/chutes/node-attestation.json), [appraisal code](../packages/chutes/src/evidence.ts) |
| Privatemode mesh | A2/H3/G3/X3 under exact manifest admission; fresh Coordinator does not make all workers fresh | [Credentialed SDK/source validation](evidence/providers/privatemode-validation.md), [manifest modes and custody](providers/privatemode.md) |

Tinfoil public workers are the sole implemented public-code baseline. Other implemented paths need explicit provider/host trust. Privatemode's A2 ranks ahead of A3 under code-first route ordering, without upgrading its hardware or handling.

## Prospective paths

These are dated investigated paths without installed adapters. The linked record supplies exact source pins and settlement conditions. H1 below means only the returned verified CPU/key closure, not established routing to every eventual plaintext recipient.

| Provider / path | Dated conservative A/H/G/X | Deciding scope / evidence |
| --- | --- | --- |
| Confidential AI | A3 / H1* / G3 / X3 | [Operator/state-disk access and sampled front-door + six receipts](evidence/providers/2026-10-09-anonymous-verification.md#confidential-ai); actual request routing/mounts/workload use expressly unproven |
| Cohere Model Vault | A3† / H3 / G3 / X3 | [Runtime executable/key closure unresolved; Passport lacks client nonce](evidence/providers/2026-10-09-anonymous-verification.md#cohere-model-vault) |
| Phala / RedPill | A3 / H3 / G3 / X3 | [Mutable upstream routing and incomplete downstream evidence](evidence/providers/2026-10-09-anonymous-verification.md#phala--redpill); legacy fresh gateway quote cannot upgrade the closure |
| Venice, NEAR sample | A3 / H2 / G3 / X3 | [Nonce-bound OutOfDate worker sample](evidence/providers/2026-10-09-anonymous-verification.md#venice); no same-connection TLS appraisal in that probe |
| Venice, Phala sample | A3 / H3 or out of scope / G3 / X3 | [Gateway quote lacks complete serving-worker evidence](evidence/providers/2026-10-09-anonymous-verification.md#venice) |
| Nillion nilAI | A3 / H3 / G3 / X3 | [Runtime inputs and nonce not passed to attester](evidence/providers/2026-10-09-anonymous-verification.md#nillion-nilai) |
| Secret AI / SecretVM | A3† / H3 / G3 / X3 | [Serving closure unresolved; static CPU resource/server GPU nonce](evidence/providers/2026-10-09-anonymous-verification.md#secret-ai--secretvm) |
| CONFSEC / OpenPCC | A3† / H3 / G3 / X3 | [Signed root exists, runtime/key closure unresolved; node TPM nonce](evidence/providers/2026-10-09-anonymous-verification.md#confsec--openpcc) |
| Prem AI | A3 / H3† / G3 / X3 | [Empty default image pins; valid-width nonce probe 403](evidence/providers/2026-10-09-anonymous-verification.md#prem-ai); 403 is not a firmware verdict |
| Cocoon ordinary proxy route | A3 / H3 / G3 / X3 | [Attested proxy plaintext/runtime-authority gap; key-only CPU quote](evidence/providers/2026-10-09-anonymous-verification.md#cocoon-proxy-plaintext-attestation-and-authority); optional inner encryption needs separate worker proof |
| io.net / NanoGPT documented gateways | Out of scope | [Public plaintext gateway boundary not closed by available CPU/key evidence](evidence/providers/2026-10-09-anonymous-verification.md#out-of-scope-rows-and-the-broad-group) |
| Maple / OpenGradient | Outside supported CPU model | [Real Nitro evidence does not supply a TDX/SNP floor; external inference closure separate](evidence/providers/2026-10-09-anonymous-verification.md#out-of-scope-rows-and-the-broad-group) |
| Hyperscalers, Apple, Google and other rule-outs | Broad universal absence claim unresolved | [Named product evidence and limits](evidence/providers/2026-10-09-anonymous-verification.md#out-of-scope-rows-and-the-broad-group), [original bounded search](evidence/providers/2026-10-08-survey.md#ruled-out-quickly); no newly verified absence/availability/pricing claim |

A3/H3/G3/X3 would require `trust-provider-and-host` if an adapter established in-scope CPU evidence. A3/H2/G3/X3 additionally admits `host=outdated-firmware`; a complete H1 path would admit `host=current`. These are hypothetical thresholds, not implemented product support.

## Reconciled conclusions

- **Chutes H:** anonymous evidence lacked the ML-KEM key needed to verify `SHA256(nonce_hex + key_base64)`; the key endpoint returned 401. H3† in that record was an unresolved freshness check, not proof of a stale quote. Later credentialed adapter evidence authenticates the missing binding and locally rates each accepted instance H1/H2. The original anonymous verdict remains intact. Earlier H200/PPCIe observations do not describe the later decoded Blackwell/MPT sample; G3 remains because complete serving coverage is unproven.
- **Privatemode reproduction:** Nix-rebuilding a subset does not establish an A1 plaintext/key closure, authenticated public release identity or review approval. A future full solution must also establish an X limit. With H3/G3 and X2, an illustrative policy would be `public-builds-trust-host,egress=metadata`; X1 cannot be assumed. B1/B2 reproduction and S1/S2 review admission are unsupported in this implementation. The earlier “could reach A1 without provider help” proposal remains historical/unverified.
- **Remote GPU verdicts:** NRAS is an allowed explicit service-trust choice under the current model. Signed overall/device authenticity, freshness, complete serving count, CPU binding, protected mode, reference/revocation and floors still apply. A generic JWT or an in-guest-only result cannot establish those properties; using NRAS alone is not a categorical disqualification. [Current shared checks](../packages/core/src/nras.ts), [GPU rating](../packages/core/src/gpu-appraisal.ts).
- **Model weights:** downloading unpinned data-only weights does not automatically make code A3. Executable loaders/assets, mutable configuration and key custody decide the code closure. Cohere/OpenPCC/Secret AI remain unresolved on those grounds; the original weight rationale is not retained as a current rule.
- **Old strict bar:** its no-egress/no-log/local-only-GPU requirements and absolute “no other provider can qualify” conclusion describe the original investigation. Current graded admission permits X2 metadata and explicitly trusted hardware gaps; no stronger public-build qualification is inferred from that change.

## Evidence access and maintenance

The anonymous record refers to private receipts without public stable receipt IDs/digests or retrieval instructions. Its pinned source links are independently inspectable; unlinked raw probes cannot be fully reproduced from the repository. No receipt IDs or verification were invented here. New records must follow the [evidence requirements](evidence/README.md#recording-and-maintaining-observations), preserve failed rows, and name exact commit/dependencies, population and authenticated versus decoded fields. Revisit applicability after adapter, authority, floor or SDK changes; use a fresh scoped record to change a qualification.

Written by Codex.

## Earlier investigation links

Retained fragments lead to the preserved survey, without a second current specification.

<a id="ratings-under-the-security-model"></a>

- [Ratings under the security model](evidence/providers/2026-10-08-survey.md#ratings-under-the-security-model)

<a id="original-bar-the-public-build-requirements"></a>

- [Original bar: the public-build requirements](evidence/providers/2026-10-08-survey.md#original-bar-the-public-build-requirements)

<a id="verdict-table"></a>

- [Verdict table](evidence/providers/2026-10-08-survey.md#verdict-table)

<a id="what-the-near-misses-would-need"></a>

- [What the near misses would need](evidence/providers/2026-10-08-survey.md#what-the-near-misses-would-need)

<a id="per-provider-evidence"></a>

- [Per-provider evidence](evidence/providers/2026-10-08-survey.md#per-provider-evidence)

<a id="privatemode-edgeless-systems"></a>

- [Privatemode (Edgeless Systems)](evidence/providers/2026-10-08-survey.md#privatemode-edgeless-systems)

<a id="confidential-ai-formerly-lunal"></a>

- [Confidential AI (formerly Lunal)](evidence/providers/2026-10-08-survey.md#confidential-ai-formerly-lunal)

<a id="chutes"></a>

- [Chutes](evidence/providers/2026-10-08-survey.md#chutes)

<a id="cohere-model-vault-encrypted"></a>

- [Cohere Model Vault Encrypted](evidence/providers/2026-10-08-survey.md#cohere-model-vault-encrypted)

<a id="phala-private-ai--redpill"></a>

- [Phala Private AI / RedPill](evidence/providers/2026-10-08-survey.md#phala-private-ai--redpill)

<a id="venice"></a>

- [Venice](evidence/providers/2026-10-08-survey.md#venice)

<a id="cocoon-telegram-ton"></a>

- [Cocoon (Telegram, TON)](evidence/providers/2026-10-08-survey.md#cocoon-telegram-ton)

<a id="nillion-nilai"></a>

- [Nillion nilAI](evidence/providers/2026-10-08-survey.md#nillion-nilai)

<a id="secret-ai--secretvm"></a>

- [Secret AI / SecretVM](evidence/providers/2026-10-08-survey.md#secret-ai--secretvm)

<a id="confident-security-confsec--openpcc"></a>

- [Confident Security CONFSEC / OpenPCC](evidence/providers/2026-10-08-survey.md#confident-security-confsec--openpcc)

<a id="prem-ai"></a>

- [Prem AI](evidence/providers/2026-10-08-survey.md#prem-ai)

<a id="ionet-nanogpt-maple-opengradient"></a>

- [io.net, NanoGPT, Maple, OpenGradient](evidence/providers/2026-10-08-survey.md#ionet-nanogpt-maple-opengradient)

<a id="ruled-out-quickly"></a>

- [Ruled out quickly](evidence/providers/2026-10-08-survey.md#ruled-out-quickly)

<a id="method-and-limits"></a>

- [Method and limits](evidence/providers/2026-10-08-survey.md#method-and-limits)
