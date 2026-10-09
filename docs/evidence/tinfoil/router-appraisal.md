# Tinfoil router appraisal

Observed 2026-10-09 from macOS on Node 26.10 against the branch that replaced Tinfoil's SDK on the router route. The route-wide rating stays A3/H3/G3/X3; this record covers only the router component.

## What the SDK did not check

Tinfoil's `SecureClient` 1.2.2 appraised the router from a prebuilt attestation bundle carrying no client nonce. It authenticated the router's signed tag but not its build workflow or runner, did not apply pi-tee's firmware floors, and on an EHBP key-configuration mismatch re-attested and resent the same request once.

## Live observations

- Tinfoil's router inventory for SEV-SNP lists more than one host. pi-tee pins only `inference.tinfoil.sh`, the SDK's own base URL.
- `inference.tinfoil.sh/.well-known/tinfoil-attestation?nonce=…` returned v3 evidence bound to the client's fresh nonce: AMD Genoa SEV-SNP, `tinfoilsh/confidential-model-router` v0.0.155.
- The bundled helper accepted it in `--router` mode with the document's AMD revocation list and the production platform policy. Microcode is below pi-tee's local Genoa floor and above the publisher minimum, so the component rates H2.
- The router code's Sigstore bundle names the public `tinfoil-release-publish.yml` workflow at `refs/tags/v0.0.155` on GitHub-hosted runners. The same bundle is rejected as a model publisher, and model bundles are rejected in router mode ([router tests](../../../tools/tinfoil-public-build/router_test.go)).
- The live TLS certificate's SPKI SHA-256 equals the attested `tls` key, so TLS terminates inside the appraised guest.
- One synthetic `gpt-oss-120b` request through `createTinfoilProvider({ route: "router" })` completed with `stop`, after a fresh appraisal, sealed to the attested HPKE key over that pinned TLS.

## Limits

The router decrypts each request and forwards it to workers whose code, CPU and GPU evidence never reach the client. If `inference.tinfoil.sh` is served by several enclaves, the attestation request and the dispatch can reach different ones; the pinned TLS key then fails the dispatch closed with no resend. Reproduce with `npm run smoke:attestation`, which appraises the router without credentials or inference.
