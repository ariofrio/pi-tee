# Commands and settings

Replace `<provider>` with `nearai`, `tinfoil`, `chutes` or `privatemode`.

| Command | Behavior |
| --- | --- |
| `/login <provider>` | Pi secret prompt and native credential storage; no browser OAuth |
| `/logout <provider>` | Pi removes the stored credential |
| `/<provider> status` | Actual request levels, trust, gaps, observations and route choice; never credentials or content |
| `/<provider> policy <setting>` | Same [policy grammar](policy.md); provider-only, aborts active requests, session-only |
| `/<provider> models` | Inspect model discovery |
| `/<provider> models refresh` | Force catalog refresh; Privatemode uses the native credential |
| `/nearai models all` / `/nearai models tee` | Session visibility choice; labeled non-TEE entries still cannot dispatch |

| Environment | Meaning |
| --- | --- |
| `PI_TEE_POLICY` | Shared initial policy; omitted uses `public-builds,egress=metadata` |
| `NEARAI_API_KEY`, `TINFOIL_API_KEY`, `CHUTES_API_KEY`, `PRIVATEMODE_API_KEY` | Provider credential fallback; Pi's stored key wins |
| `PI_TEE_OFFLINE=1` | Skip startup discovery; does not authorize offline evidence or inference |
| `PI_NEARAI_MODEL_VISIBILITY=tee` / `all` | Default TEE-only visibility versus labeled full catalog |
| `PI_PRIVATEMODE_MANIFEST_MODE=hard-pin` / `logged-cdn` | [Manifest admission](../providers/privatemode.md#manifest-admission); hard-pin is default |
| `PI_PRIVATEMODE_MANIFEST_PATH` | Immutable local manifest captured at provider creation; cannot combine with logged-CDN |

Pi stores model snapshots with four-hour freshness checks. Failed refresh keeps the previous models; direct endpoint availability is adapter-owned and is not persisted in snapshots. Catalog timestamps do not extend evidence expiry. Model capabilities, prices and TEE labels are provider claims.

Tinfoil caches authenticated immutable artifacts and deterministic helper results in memory, plus two verified GitHub API lookups in an owner-only `pi-tee/github-metadata` directory under absolute `$XDG_CACHE_HOME` or `~/.cache`. Fresh CPU challenges, GPUs, keys and witness acceptance are never cached. Privatemode's admission journal is `pi-tee/privatemode/manifest-admissions.jsonl` under `$XDG_STATE_HOME` (default `~/.local/state`), with new directories/files at 700/600. It records digests, sources and time, without credentials/content/quotes.

[Removed variables and policy migration](policy.md#migration). Live harness settings belong in [validation procedures](../procedures/live-validation.md).
