# Documentation archive

[The scope and commit index](reviews/README.md) pairs the original findings with their follow-ups. Historical reviews preserve their original scope, findings, conditions and verdicts. They do not review today's `main`. Current obligations remain in [CONTRIBUTING](../../CONTRIBUTING.md), [SECURITY](../../SECURITY.md), the [security model](../security-model.md) and the [Tinfoil serving contract](../tinfoil-public-profile.md).

| Material | Location |
| --- | --- |
| Original design review and resolutions | [Design review](reviews/design-review.md), [resolutions](reviews/review-resolution.md) |
| Fixed-commit implementation reviews | [Public build](reviews/pi-tee-public-build-opus-review.md), [public session](reviews/pi-tee-public-session-opus-review.md), [local setup](reviews/pi-tee-local-setup-opus-review.md), [enablement](reviews/pi-tee-enablement-opus-review.md), [multi-model/SNP/TLS](reviews/pi-tee-multimodel-snp-tls-opus-review.md) |
| Dated validation and source investigations | [Evidence index](../evidence/README.md) |

Moves use `git mv`. Old cited paths keep compatibility pages and their linked headings during the provider-branch transition. Git history retains original locations and exact text; use `git log --follow --find-copies=20% --find-copies-harder -- <path>` (copy detection also traces moves whose old paths remain as compatibility pages) to trace a moved file. Remove compatibility pages only after inbound links and external citations have been accounted for.
