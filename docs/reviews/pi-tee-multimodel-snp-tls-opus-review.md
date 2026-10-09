# Opus 5.5 review B: multi-model / SEV-SNP public-build profile and pinned TLS client at `520f0ae` (+ `246891b`)

This historical report moved to the [archive](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md). Its findings and verdict are preserved with their original scope. See the [scope and commit index](../archive/reviews/README.md) for follow-ups.

## Verdict: enable after fixes

See [Verdict: enable after fixes](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#verdict-enable-after-fixes).

## Findings

See [Findings](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#findings).

## F1 — SEV-SNP Genoa floors predate AMD's SEV-SNP fixes, and the live Genoa fleet is unpatched against two of them

See [F1 — SEV-SNP Genoa floors predate AMD's SEV-SNP fixes, and the live Genoa fleet is unpatched against two of them](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#f1--sev-snp-genoa-floors-predate-amds-sev-snp-fixes-and-the-live-genoa-fleet-is-unpatched-against-two-of-them).

## F2 — The engine image's entrypoint and environment are outside the runtime profile; DeepSeek's entrypoint is an undeclared plaintext proxy

See [F2 — The engine image's entrypoint and environment are outside the runtime profile; DeepSeek's entrypoint is an undeclared plaintext proxy](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#f2--the-engine-images-entrypoint-and-environment-are-outside-the-runtime-profile-deepseeks-entrypoint-is-an-undeclared-plaintext-proxy).

## F3 — Node process crash on a malformed response header from the pinned peer

See [F3 — Node process crash on a malformed response header from the pinned peer](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#f3--node-process-crash-on-a-malformed-response-header-from-the-pinned-peer).

## F4 — No backpressure: buffering is unbounded behind the "bounded" limiter

See [F4 — No backpressure: buffering is unbounded behind the "bounded" limiter](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#f4--no-backpressure-buffering-is-unbounded-behind-the-bounded-limiter).

## F5 — Close-delimited bodies accepted without `close_notify`

See [F5 — Close-delimited bodies accepted without `close_notify`](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#f5--close-delimited-bodies-accepted-without-close_notify).

## F6 — Bun does not enforce TLS 1.3

See [F6 — Bun does not enforce TLS 1.3](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#f6--bun-does-not-enforce-tls-13).

## F7 — Stale user-visible assumptions

See [F7 — Stale user-visible assumptions](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#f7--stale-user-visible-assumptions).

## F8 and F9 — Info

See [F8 and F9 — Info](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#f8-and-f9--info).

## Verified correct (scope items 1–7)

See [Verified correct (scope items 1–7)](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#verified-correct-scope-items-17).

## Documentation claims versus enforcement

See [Documentation claims versus enforcement](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#documentation-claims-versus-enforcement).

## Conditions for enablement

See [Conditions for enablement](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#conditions-for-enablement).

## Re-review at `ad71a91` (fixes `0e3add3`, `ea382e6`, `8b33709`)

See [Re-review at `ad71a91` (fixes `0e3add3`, `ea382e6`, `8b33709`)](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#re-review-at-ad71a91-fixes-0e3add3-ea382e6-8b33709).

## Verdict: enable

See [Verdict: enable](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#verdict-enable).

## Status of each finding

See [Status of each finding](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#status-of-each-finding).

## New code in `ea382e6`

See [New code in `ea382e6`](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#new-code-in-ea382e6).

## Re-run results at `ad71a91`

See [Re-run results at `ad71a91`](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#re-run-results-at-ad71a91).

## Consequence to note

See [Consequence to note](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#consequence-to-note).

## Enablement review at `94b43a7`

See [Enablement review at `94b43a7`](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#enablement-review-at-94b43a7).

## Verdict: enable (approve the merge), with two conditions before pushing

See [Verdict: enable (approve the merge), with two conditions before pushing](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#verdict-enable-approve-the-merge-with-two-conditions-before-pushing).

## The enablement commit

See [The enablement commit](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#the-enablement-commit).

## `ecc5cd0` and `6ea1329` (TLS and probing)

See [`ecc5cd0` and `6ea1329` (TLS and probing)](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#ecc5cd0-and-6ea1329-tls-and-probing).

## Regression checks at `94b43a7`

See [Regression checks at `94b43a7`](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#regression-checks-at-94b43a7).

## Delta review: `d0bd843` and the rebased enablement commit

See [Delta review: `d0bd843` and the rebased enablement commit](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#delta-review-d0bd843-and-the-rebased-enablement-commit).

## Verdict: enable

See [Verdict: enable](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#verdict-enable-1).

## `d0bd843`

See [`d0bd843`](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#d0bd843).

## Checks at `dbbec6f` (code identical to `e6cb1b7`)

See [Checks at `dbbec6f` (code identical to `e6cb1b7`)](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#checks-at-dbbec6f-code-identical-to-e6cb1b7).

## Post-merge delta: `7b8ee9f` and `5fbe387`

See [Post-merge delta: `7b8ee9f` and `5fbe387`](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#post-merge-delta-7b8ee9f-and-5fbe387).

## Verdict: OK

See [Verdict: OK](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#verdict-ok).

## `7b8ee9f` resolves the Low hardening item from the delta review

See [`7b8ee9f` resolves the Low hardening item from the delta review](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#7b8ee9f-resolves-the-low-hardening-item-from-the-delta-review).

## `5fbe387`: per-entry persistence

See [`5fbe387`: per-entry persistence](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#5fbe387-per-entry-persistence).

## Checks at `5fbe387`

See [Checks at `5fbe387`](../archive/reviews/pi-tee-multimodel-snp-tls-opus-review.md#checks-at-5fbe387).
