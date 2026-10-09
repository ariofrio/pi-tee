# Architecture and design rationale

User-facing contracts live in the [security model](../security-model.md) and [provider guide](../providers.md). This document explains why the local boundaries exist. The complete earlier investigations and source citations remain in the [design snapshot](../evidence/client/2026-10-09-design-assessment.md); old reviews are indexed by [scope/commit](../archive/reviews/README.md).

## Owned sessions and final payloads

An adapter opens a candidate without receiving a prompt, returns only established request levels and owns its transport. Core admits/ranks it under the unchanged policy, disposes losing sessions and prevents use after evidence expiry or a policy-epoch change. This ties canonical model, authority-policy identity, authenticated artifact digests and endpoint keys to one dispatch rather than to untrusted discovery metadata. Keys remain private to the transport; the public admission record omits them. [TeeRouteDefinition / run()](../../packages/core/src/provider.ts).

Pi converts messages and runs payload hooks after candidate setup. The final guard therefore checks the serialized request at the transport boundary, fixing model, endpoint/authentication and accepted fields. Guarding an earlier message object would leave hook mutations and SDK-added dispatches outside the check. [guardChatFetch()](../../packages/core/src/transport.ts).

Socket ownership ensures the key checked is the key receiving the request. A separately verified connection followed by ordinary fetch could reconnect or resend, invalidating that binding. NEAR direct needs WebPKI plus appraised SPKI on one reusable socket for evidence/inference/signatures; Tinfoil direct uses appraised SPKI as endpoint authority. Unattested relays instead receive an explicit credential/metadata exception while bodies are sealed to authenticated keys. Chutes owns even the WebPKI invocation socket to prevent a runtime HTTP 421 resend. [TLS boundary](../../packages/core/src/pinned-tls.ts), [NEAR channel](../../packages/nearai/src/direct-channel.ts).

## Trust declarations

Local policy fixes authorities/rules; authenticated release evidence fixes one session's bytes. Repository, workflow, root, required security property or recipient changes require an explicit policy change. Compatible releases within accepted identities can update automatically. Publisher attribution authorizes a release; it does not independently rebuild or approve it. Fresh endorsement permits an older release and cannot imply newest-release or immediate revocation.

Hardware authentication cannot supply missing runtime/key-custody guarantees. Every plaintext/key recipient contributes its weakest level, including hidden sidecars, shared-key workers, secret services and downstream gateways. A shared-key signature proves a key holder, without exclusive serving-instance identity. Provider-assembled lists below A1 cannot establish complete GPU coverage. [weakestRoute()](../../packages/core/src/security.ts), [Tinfoil declared closure](../contracts/tinfoil-public-builds.md).

## Serving-path requirements

A public production profile must establish fresh manufacturer-authenticated CPU evidence; authenticated guest/configuration/container/model/tokenizer inputs before use; complete CPU-bound serving-GPU evidence and protected transfers/fabric; keys confined to admitted software for their lifetime; and a connection bound to those keys before dispatch. Every decrypting hop must obey the same selected policy. A published check must actually execute on the serving path; provenance cannot add a missing protected channel. [Production obligations](../../SECURITY.md#required-closed-inventory), [qualification procedure](../procedures/verify-provider.md).

## Pi integration and request lifecycle

Keep separately installable providers and shared enforcement. Catalog capability/protocol support are independent of admission; offline snapshots and four-hour refresh never extend evidence lifetime. Native login/store precedence, tools, reasoning, usage and cancellation belong to Pi's provider interface; adapters supply only provider differences. [createTeeProvider()](../../packages/core/src/provider.ts), [adapter API overview](../../packages/core/README.md).

After the final guard, send through the owned encrypted transport, authenticate output before text/tool exposure, then dispose on completion, cancellation or terminal error. Sanitized fixed error codes stop Pi's request/turn retry classifiers from replaying a potentially executed request. The disclosed Tinfoil SDK router recovery remains a route-specific exception. Local verifier workers never receive prompts/API keys; only explicit NRAS uploads GPU evidence.

Whole-session confidentiality additionally needs a Pi guard after physical-provider resolution, covering model switches, fallback, summaries, compaction and background calls. Pi catches request-hook exceptions, so an extension hook alone cannot enforce that boundary. [Pinned hook behavior](https://github.com/earendil-works/pi/blob/eb326d265ae0b88489a6d10319307780df827cdf/packages/coding-agent/src/core/agent-session.ts).

## Module organization

Core's provider module currently owns lifecycle, admission, catalog publication and status; transport guards combine payload validation and networking, while Tinfoil's artifact chain combines fetching, authentication and cache management. Comments now explain the boundaries beside their symbols. Future refactors should split responsibilities only with invariant-preserving seam tests; no refactor is included in this documentation change.
