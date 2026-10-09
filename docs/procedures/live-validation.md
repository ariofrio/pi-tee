# Live validation

Run required offline checks first. Existing outcomes live in the [evidence index](../evidence/README.md). Use the locked client/dependencies, synthetic capped prompts and an isolated credential store. Live inference is opt-in and billable; documentation edits do not require a new paid run.

The [Pi harness](../../scripts/live-pi.ts) loads the native extension, checks stored-key precedence, streamed text/usage, Unicode tools/follow-up, reasoning and RPC cancellation. Load only the needed credential into its process:

```sh
PI_TEE_POLICY=public-builds,egress=metadata node --env-file=/path/to/private/tinfoil.env \
  --import tsx scripts/live-pi.ts tinfoil deepseek-v4-1-flash --public-builds
PI_TEE_POLICY=trust-provider-and-host,host=current node --env-file=/path/to/private/nearai.env \
  --import tsx scripts/live-pi.ts nearai z-ai/glm-5.3-flash --direct
PI_TEE_POLICY=trust-provider-and-host,host=current node --env-file=/path/to/private/chutes.env \
  --import tsx scripts/live-pi.ts chutes Qwen/Qwen3.8-27B-TEE
PI_TEE_POLICY=trust-provider-and-host,code=fixed-private node --env-file=/path/to/private/privatemode.env \
  --import tsx scripts/live-pi.ts privatemode gpt-oss-120b
```

Bun reads TypeScript directly: replace `node --env-file=... --import tsx` with `bun --env-file=...`. Set `PI_TEE_LIVE_PI_BINARY` to an absolute Pi binary to qualify a compiled runtime. Tinfoil `--public-builds --gateway` explicitly exercises the production billing relay even when direct qualifies. NEAR `--direct` asserts discovered direct selection and observed policy levels. `--public-builds-candidate` is an isolated adapter test, not production-route qualification.

Append `--cancel-stream` to abort after a live text delta without the full suite's consumption barrier; `--cancel-only` covers cancellation at response headers. Record local acknowledgement separately from remote generation-stop timing, which neither check establishes. The harness removes its temporary credential store and excludes keys/payloads from output.

## Evidence-only checks

Catalog/worker/attestation smokes send no inference: `npm run smoke:catalogs`, `smoke:workers`, `smoke:attestation`, and `smoke:near-gpu`. [Chutes attestation sampler](../../scripts/live-chutes-attestation.ts) requires discovery credentials without inference. Privatemode's real SDK negatives require credentials for bootstrap/key exchange, without inference:

```sh
PI_PRIVATEMODE_LIVE=1 node --env-file=/path/to/private/privatemode.env \
  --import tsx --test tests/privatemode-live.test.ts
```

Record commit/lock/runtime, model/route/population, rejected cases, authenticated versus decoded fields, billing scope, skips and sanitized receipt links. Never publish secrets, raw evidence or transcripts. [Record requirements](../evidence/README.md#recording-and-maintaining-observations).
