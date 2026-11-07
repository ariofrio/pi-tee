# Tinfoil router appraisal

Observed 2026-10-09 from macOS on Node 26.10 against the branch that replaced Tinfoil's SDK on the router route. The route-wide rating stays A3/H3/G3/X3; this record covers only the router component.

## What the SDK did not check

Tinfoil's `SecureClient` 1.2.2 appraised the router from a prebuilt attestation bundle carrying no client nonce. It authenticated the router's signed tag but not its build workflow or runner, did not apply pi-tee's firmware floors, and on an EHBP key-configuration mismatch re-attested and resent the same request once.

## Live observations

- Tinfoil's router inventory for SEV-SNP lists more than one host. pi-tee pins only `inference.tinfoil.sh`, the SDK's own base URL.
- `inference.tinfoil.sh/.well-known/tinfoil-attestation?nonce=…` returned v3 evidence bound to the client's fresh nonce: AMD Genoa SEV-SNP, `tinfoilsh/confidential-model-router` v0.0.155.
- The bundled helper accepted it in `--router` mode with the document's AMD revocation list and the production platform policy. Microcode is below pi-tee's local Genoa floor and above the publisher minimum, so the component rates H2.
- The router code's Sigstore bundle names the public `tinfoil-release-publish.yml` workflow at `refs/tags/v0.0.155` on GitHub-hosted runners. The same bundle is rejected as a model publisher, and model bundles are rejected in router mode ([router tests](../../../tools/tinfoil-public-build/router_test.go)).
- The live TLS certificate's SPKI SHA-256 equals the attested `tls` key, so TLS terminates at a holder of the key the appraised guest's report binds. The client cannot tell whether that private key also exists elsewhere.
- One synthetic `gpt-oss-120b` request through `createTinfoilProvider({ route: "router" })` completed with `stop`, after a fresh appraisal, sealed to the attested HPKE key over that pinned TLS.

## 2026-11-07: signed firmware member

From 852279d, every router appraisal failed with `TEE_PUBLIC_BUILD_REJECTED`. `inference.tinfoil.sh` served `tinfoilsh/confidential-model-router` v0.0.171 on SEV-SNP. The helper's router mode returned `TEE_PUBLIC_BUILD_BINDING_REJECTED` from [`codePredicate()`](../../../tools/tinfoil-public-build/release.go): the signed `snp-tdx-multiplatform/v1` predicate carried an unknown `firmware` member, `{"sev_snp":{"type":"ovmf","version":"v0.0.4","sha256":"78c89017…c1c4"}}`. Router releases from [v0.0.156](https://github.com/tinfoilsh/confidential-model-router/releases/tag/v0.0.156) (2026-10-12) onward carry it; v0.0.155 did not. Tinfoil's own verifier reads only the measurement and shape members.

Router mode never recomputed the launch digest: the authenticated release fixes the measurement, whatever firmware it was computed with. Decoding the member strictly therefore admits no new signer, release or measurement. After the change, fresh evidence from the same release passed `--router` with H2, and `kimi-k3-1-pro` and `deepseek-v4-1-flash` requests under `trust-provider-and-host` each completed through the router with `stop` on Node 26.10.

## Limits

The router decrypts each request and forwards it to workers whose code, CPU and GPU evidence never reach the client. If `inference.tinfoil.sh` is served by several enclaves, the attestation request and the dispatch can reach different ones. A backend with different keys fails the pinned TLS or HPKE key and ends the dispatch with no resend; one sharing both keys is indistinguishable from the appraised guest. Reproduce with `npm run smoke:attestation`, which appraises the router without credentials or inference.
