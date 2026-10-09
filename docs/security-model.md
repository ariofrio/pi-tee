# Security model

A policy names who you trust and sets admission thresholds. Levels describe what the client verified for the current request. Unchecked properties receive the weakest level; the weakest component that holds plaintext or a serving key determines each route-wide level. Routes without verified CPU evidence are outside this model.

Verified means hardware/manufacturer signatures checked by the client, or output of code verified at A1. Claims assembled by code below A1 cannot establish complete serving coverage or handling limits. Intel, AMD and NVIDIA as manufacturers, your machine, Pi and enabled local code are always trusted. Physical attacks on the serving host are outside the model.

## Levels

| Axis | Values, strongest to weakest | Verified meaning |
| --- | --- | --- |
| A: code | `public-release`, `fixed-private`, `provider-controlled` | A1 identifies publicly logged releases from pinned repositories and workflows, including the guest, configuration, runtime and key-custody chain. A2 pins all plaintext-capable private code but cannot inspect its behavior. A3 cannot establish which serving code runs or whether it changes. |
| H: host | `current`, `outdated-firmware`, `stale` | H1 binds CPU evidence to the client's fresh nonce and checks local firmware floors. H2 is fresh but below those floors, or cannot establish them. H3 checks evidence without a fresh nonce or local floors. |
| G: GPU | `verified`, `gaps`, `unchecked` | G1 authenticates every serving GPU, complete serving coverage, CPU-hashed evidence, local floors, and SPT or Blackwell MPT. G2 retains authenticity, freshness, confidential mode and complete coverage but permits documented gaps. G3 lacks complete serving evidence. |
| X: handling | `none`, `metadata`, `any` | X1 permits no egress or plaintext storage. X2 permits only fixed-destination authorization metadata, without body egress or storage. X3 cannot establish such limits. |
| B: build | `reproduced-off-github`, `reproduced`, `publisher-workflow`, `signed` | B1 reproduces off GitHub; B2 reproduces through an already trusted party on GitHub; B3 checks the named publisher workflow and hosted runner, including its endorsed engine artifacts; B4 checks a repository's signed release tag without checking workflow or runner. |
| S: review | `pinned`, `window`, `none` | S1 adds independent approval and pins; S2 requires a review interval in the public signing log; S3 imposes neither. |

Weights count as code when executed. Downloading data-only weights does not by itself imply A3; executable loaders, configuration changes and key custody must be assessed. The admitted Tinfoil runtime rejects remote model code. Output correctness is outside the contract.

G2 gaps are unranked: Hopper PPCIe with unattested NVSwitches, nonce-only CPU–GPU association, or signed, unrevoked firmware below local floors. G1/G2 require fresh CPU evidence and complete serving coverage. CPU-only plaintext components meet any GPU threshold. [Hardware policy](reference/hardware-policy.md) owns exact floors; valid collateral can still lag a new revocation.

B3 and S3 are the only implemented build/review admission refinements. Public code trusts its named publishers, workflow writers and accepted build processes to authorize compatible updates automatically. Public evidence enables auditing; it cannot guarantee safe publisher behavior or detection before an authorized malicious release runs. The [Tinfoil serving contract](contracts/tinfoil-public-builds.md) declares its authorities, recipients and update rules.

## Admission and selection

The four positions name provider/host trust; complete defaults and forced combinations live in the [policy reference](reference/policy.md). If a trusted host is the provider or colludes with it, a host-trusting public-build position effectively trusts both. Status reports this caveat.

A route must meet every threshold. Qualifying routes are compared by code, then host, GPU and handling. Build/review constrain admission, not tie-breaking. Public code can therefore outrank stronger hardware on provider-controlled code. Discovery and potential levels only filter candidates; they are never verified request levels. Failed or unavailable candidates never relax policy or authorize content transmission.

Every plaintext/key recipient counts, including routers, sidecars, KMS, secret services, other workloads sharing a key and downstream engines. A signature with shared custody cannot establish exclusive serving-instance identity. [Implemented routes](providers.md) disclose their actual gaps and credential exceptions.

`verifier=local` is the default. Opt-in NRAS authenticates NVIDIA's overall and detached device tokens, then applies the same mode, coverage, count, freshness, certificate/reference and firmware checks. It adds trust in service keys, insiders and appraisal policy; discloses GPU identity and attestation timing to NVIDIA; and depends on service availability. A remote verdict alone cannot qualify a route. [Settings and no-effect cases](reference/policy.md#forced-values-and-categories).

## Status and commitments

`/<provider> status` shows the position, thresholds, permitted trust, actual levels, computed gaps, observed details and candidate decisions. Before verification, levels are not established. Reports omit credentials, prompts, completions and quote bodies. Manufacturer authentication does not establish a complete safe software inventory or exclusive key custody.

C (commitments) is displayed separately from admission. Contractual retention/training/audit statements do not prove deployed handling or raise a level. [NEAR's dated source/terms record](evidence/nearai/commitments.md) retains the original observations; other provider commitments have not been appraised by these adapters.

Successful public dispatch reports `publicBuildVerification: profile-established` and `closedTrustSet: profile-declared`: checks passed under the declared contract, without an independently proven complete inventory. `independentApproval` and `protectedSession` remain `not-established`. [Protection boundary and obligations](../SECURITY.md).

## Earlier section links

<a id="policy-setting"></a>

See [Policy setting](reference/policy.md).

<a id="forced-values-and-categories"></a>

See [Forced values and categories](reference/policy.md).

<a id="routes-and-selection"></a>

See [Routes and selection](reference/policy.md).

<a id="migration"></a>

See [Migration](reference/policy.md).
