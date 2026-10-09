import assert from "node:assert/strict";

// Public, credential-free check of the NEAR direct route's evidence: a fresh
// client nonce, the owned TLS channel, Intel quote verification and NVIDIA's
// local GPU verifier under the route's default GPU policy, which fails closed
// on hardware it does not admit. Reports NVIDIA's verdict either way.
// No inference; nothing is saved.
const contacted = new Set<string>();
const realFetch = globalThis.fetch;
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  contacted.add(new URL(new Request(input, init).url).host);
  return realFetch(input, init);
}) as typeof fetch;
// Imported after the recorder: the SDK's quote verifier keeps the fetch it sees at load.
const { DirectAttestationClient, verifyDirectModelAttestations } = await import("@nearai/inference-sdk/node");
const { NearDirectChannel } = await import("../packages/nearai/src/direct-channel.js");
const { NEAR_DIRECT_PROFILE } = await import("../packages/nearai/src/direct.js");
const { checkNearGpuEvidence } = await import("../packages/nearai/src/gpu.js");
const { runNvidiaVerifier } = await import("pi-tee-core");

const signal = AbortSignal.timeout(240000);
const channel = new NearDirectChannel(new URL(NEAR_DIRECT_PROFILE.baseUrl).origin, signal);
class Evidence extends DirectAttestationClient {
  protected override requestAttestation(request: Request) { return channel.request(request); }
  fresh() { return this.fetchModelAttestationsWithOptions({ signingAlgo: "ed25519", includeSpkiFingerprint: true }); }
}
let gpuRuns = 0;
let nvidia: Record<string, unknown> | undefined;
const started = Date.now();
try {
  const fetched = await new Evidence({ baseUrl: `${NEAR_DIRECT_PROFILE.baseUrl}/` }).fresh();
  const verified = await verifyDirectModelAttestations({
    ...fetched,
    policy: { acceptedTcbStatuses: ["UpToDate"], gpuEvidence: "required" },
    verifiers: { gpuEvidence: (payload: string) => checkNearGpuEvidence(payload, { signal, run: async options => {
      gpuRuns++;
      const result = await runNvidiaVerifier(options);
      try {
        const claims: any[] = JSON.parse(result.stdout).claims ?? [];
        nvidia = { resultCode: JSON.parse(result.stdout).result_code, gpus: claims.length, hwmodels: [...new Set(claims.map(c => c.hwmodel))],
          drivers: [...new Set(claims.map(c => c["x-nvidia-gpu-driver-version"]))], vbios: [...new Set(claims.map(c => c["x-nvidia-gpu-vbios-version"]))] };
      } catch { nvidia = { resultCode: "unparsed" }; }
      return result;
    } }) },
  });
  assert.equal(verified.tlsBinding.kind, "attested");
  channel.approve(verified.tlsBinding.spkiFingerprint);
  assert.ok(verified.attestations.every(attestation => attestation.gpuEvidence === "verified"));
  assert.ok(gpuRuns >= 1);
  assert.ok(![...contacted].some(host => host.endsWith("nvidia.com")), "The SDK contacted an NVIDIA service directly.");
  console.log(JSON.stringify({
    model: NEAR_DIRECT_PROFILE.model, attestations: verified.attestations.length, gpuAppraisals: gpuRuns,
    gpuEvidence: "verified-locally", tlsBinding: "attested", elapsedMs: Date.now() - started, hostsContactedByMainThread: [...contacted].sort(),
  }));
} catch (error) {
  // Evidence is public, but print only the classified failure.
  const code = (error as { failure?: { code?: string }; message?: string })?.failure?.code ?? (error as Error)?.message;
  console.error(`FAIL: NEAR direct evidence check: ${/^[a-z0-9_.]+$|^TEE_[A-Z_]+$|^\[/i.test(String(code)) ? code : "unclassified error"}`);
  const cause = (error as { cause?: { message?: string } })?.cause?.message;
  console.error(JSON.stringify({ gpuPolicy: /^TEE_[A-Z_]+$/.test(String(cause)) ? cause : undefined, nvidia, nvidiaContactedByMainThread: [...contacted].some(host => host.endsWith("nvidia.com")) }));
  process.exitCode = 1;
} finally {
  channel.close();
}
