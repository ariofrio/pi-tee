import { createHash, randomBytes } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { resolve, dirname, isAbsolute } from "node:path";
import { TeeError, readBoundedBody } from "pi-tee-core";
import { parseHopperGpuMode } from "./gpu-mode.js";
import { gpuVersionsAllowed } from "./gpu-policy.js";
import { verifyPublicBuildArtifacts } from "./public-build.js";

const PUBLIC_BUILD_VERIFIER_SHA256 = "08bcbf2f96f01d46c4129c0cca2e9135e76c44e1710bc51ff5cbc0652c7af1ba";

export const INTEL_CANDIDATE = Object.freeze({
  host: "gemma4-31b-inf8-0.tinfoil.containers.tinfoil.dev",
  model: "gemma4-31b",
  cpuVerifierSha256: "bcfc1896c156727a7612f4ff7500993236cd648f10e0a63e46eb2f71a3d03316",
  cpuPolicySha256: "6eacea241bd6ac37901cc3cb738f62eebb513e827d28023ffdfde719d54960b2",
  gpuImage: "sha256:b67dad12cafae0f436f21ade4b0519b5a0fb343bac4bf380d9551e96a2394b5c",
});
const nvatHashes = {
  "bin/nvattest": "0db6cba463aefa91a1a81c62bc8b3928ffe5c3d8347bde6561f5ea08dab156ae",
  "lib/libnvat.so.1.2.2": "b87d4bf93dfd0f1ffd8999d7d04db3e6a44c4048ae9b8e319f2f1cab2d885776",
  "lib/libnvat.so.1": "b87d4bf93dfd0f1ffd8999d7d04db3e6a44c4048ae9b8e319f2f1cab2d885776",
  "lib/libnvat.so": "b87d4bf93dfd0f1ffd8999d7d04db3e6a44c4048ae9b8e319f2f1cab2d885776",
};
function requireCondition(ok: unknown, code: string): asserts ok { if (!ok) throw new TeeError(code); }
async function pinnedFile(path: string, digest: string) {
  let bytes: Buffer;
  try { bytes = await readFile(path); } catch { throw new TeeError("TEE_VERIFIER_ARTIFACT_REJECTED"); }
  requireCondition(createHash("sha256").update(bytes).digest("hex") === digest, "TEE_VERIFIER_ARTIFACT_REJECTED");
}
function command(file: string, args: string[], signal: AbortSignal, input?: string, cpu = false): Promise<{ code: number; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, {
      env: cpu ? { TZ: "UTC" } : { PATH: process.env.PATH, HOME: process.env.HOME },
      signal, timeout: 60000, maxBuffer: cpu ? 4096 : 128 * 1024,
    }, (error, stdout) => {
      if (error && typeof error.code !== "number") return reject(new TeeError("TEE_VERIFIER_PROCESS_REJECTED"));
      resolve({ code: typeof error?.code === "number" ? error.code : 0, stdout });
    });
    child.stdin?.on("error", () => {});
    child.stdin?.end(input);
  });
}

export async function qualifyIntelCandidate(options: {
  cpuVerifier: string; nvatDir: string; signal: AbortSignal; evidenceFetch?: typeof globalThis.fetch;
  mode?: "frozen" | "public-builds";
}): Promise<{ tls: string; hpke: string }> {
  const { cpuVerifier, nvatDir } = options;
  const signal = AbortSignal.any([options.signal, AbortSignal.timeout(options.mode === "public-builds" ? 240000 : 90000)]);
  signal.throwIfAborted();
  requireCondition(isAbsolute(cpuVerifier) && isAbsolute(nvatDir), "TEE_VERIFIER_ARTIFACT_REJECTED");
  await pinnedFile(cpuVerifier, options.mode === "public-builds" ? PUBLIC_BUILD_VERIFIER_SHA256 : INTEL_CANDIDATE.cpuVerifierSha256);
  for (const [path, digest] of Object.entries(nvatHashes)) await pinnedFile(resolve(nvatDir, path), digest);
  const nonce = randomBytes(32).toString("hex");
  const response = await (options.evidenceFetch ?? globalThis.fetch)(`https://${INTEL_CANDIDATE.host}/.well-known/tinfoil-attestation?nonce=${nonce}`, { signal, redirect: "error" });
  requireCondition(response.ok, "TEE_ATTESTATION_REJECTED");
  const raw = await readBoundedBody(response.body, 2 * 1024 * 1024, signal);
  const envelope = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  if (options.mode === "public-builds") {
    await verifyPublicBuildArtifacts({ helperPath: cpuVerifier, raw: new TextDecoder("utf-8", { fatal: true }).decode(raw), nonce, signal, evidenceFetch: options.evidenceFetch });
  } else {
    const checked = await command(cpuVerifier, [], signal, `{"nonce":${JSON.stringify(nonce)},"envelope":${new TextDecoder("utf-8", { fatal: true }).decode(raw)}}`, true);
    const cpu = JSON.parse(checked.stdout);
    requireCondition(checked.code === 0 && cpu.cpuVerified === true && cpu.policySha256 === INTEL_CANDIDATE.cpuPolicySha256 && cpu.independentApproval === false && cpu.runtimeProviderReferenceAuthority === false, "TEE_CPU_POLICY_REJECTED");
  }
  // The strict Go parser authenticated both section byte strings before JS uses them.
  const devices = JSON.parse(Buffer.from(envelope.device_evidence, "base64").toString("utf8"));
  requireCondition(devices.items?.length === 1 && devices.items[0].id === "gpu0" && devices.items[0].kind === "gpu" && devices.items[0].vendor === "nvidia" && devices.items[0].format === "https://tinfoil.sh/format/nvidia-gpu-evidence/v1", "TEE_GPU_POLICY_REJECTED");
  const evidence = devices.items[0].evidence;
  requireCondition(evidence.nonce === nonce && evidence.arch === "HOPPER", "TEE_GPU_POLICY_REJECTED");
  const scratch = await mkdtemp(resolve(dirname(cpuVerifier), "gpu-session-"));
  const name = `pi-tee-gpu-${randomBytes(8).toString("hex")}`;
  try {
    await writeFile(resolve(scratch, "evidence.json"), JSON.stringify([evidence]), { mode: 0o600, flag: "wx" });
    const checked = await command("docker", ["run", "--rm", "--pull=never", "--name", name, "--cpus=2", "--memory=1g", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--mount", `type=bind,source=${nvatDir},target=/evidence/libnvat-linux-sbsa-1.2.2.1780962352-archive,readonly`, "--mount", `type=bind,source=${scratch},target=/fixtures,readonly`, INTEL_CANDIDATE.gpuImage, "--log-level", "off", "--format", "json", "attest", "--device", "gpu", "--gpu-evidence-source", "file", "--gpu-evidence-file", "/fixtures/evidence.json", "--verifier", "local", "--nonce", nonce], signal);
    const gpu = JSON.parse(checked.stdout);
    requireCondition(checked.code === 0 && gpu.result_code === 0 && Array.isArray(gpu.claims) && gpu.claims.length === 1, "TEE_GPU_POLICY_REJECTED");
    const c = gpu.claims[0];
    requireCondition(c.eat_nonce === nonce && c.hwmodel === "GH100 A01 GSP BROM" && c.measres === "success" && c.dbgstat === "disabled" && c.secboot === true &&
      gpuVersionsAllowed(c["x-nvidia-gpu-driver-version"], c["x-nvidia-gpu-vbios-version"], options.mode ?? "frozen") &&
      c["x-nvidia-gpu-attestation-report-signature-verified"] === true && c["x-nvidia-gpu-attestation-report-nonce-match"] === true, "TEE_GPU_POLICY_REJECTED");
    for (const field of ["x-nvidia-gpu-arch-check", "x-nvidia-gpu-attestation-report-parsed", "x-nvidia-gpu-attestation-report-cert-chain-fwid-match", "x-nvidia-gpu-driver-rim-fetched", "x-nvidia-gpu-driver-rim-measurements-available", "x-nvidia-gpu-driver-rim-signature-verified", "x-nvidia-gpu-driver-rim-version-match", "x-nvidia-gpu-vbios-rim-fetched", "x-nvidia-gpu-vbios-rim-measurements-available", "x-nvidia-gpu-vbios-rim-signature-verified", "x-nvidia-gpu-vbios-rim-version-match", "x-nvidia-gpu-vbios-index-no-conflict"]) {
      requireCondition(c[field] === true, "TEE_GPU_POLICY_REJECTED");
    }
    for (const field of ["x-nvidia-gpu-attestation-report-cert-chain", "x-nvidia-gpu-driver-rim-cert-chain", "x-nvidia-gpu-vbios-rim-cert-chain"]) {
      const chain = c[field];
      requireCondition(chain?.["x-nvidia-cert-status"] === "valid" && chain["x-nvidia-cert-ocsp-status"] === "good" && chain["x-nvidia-cert-ocsp-response-valid"] === true && chain["x-nvidia-cert-ocsp-nonce-matches"] === true, "TEE_GPU_POLICY_REJECTED");
    }
    requireCondition(parseHopperGpuMode(evidence.evidence) === "spt", "TEE_GPU_MODE_REJECTED");
  } finally {
    await new Promise<void>(resolve => execFile("docker", ["rm", "--force", name], { timeout: 10000, maxBuffer: 4096, env: { PATH: process.env.PATH, HOME: process.env.HOME } }, () => resolve()));
    await rm(scratch, { recursive: true, force: true });
  }
  signal.throwIfAborted();
  const keys = JSON.parse(Buffer.from(envelope.crypto_material, "base64").toString("utf8")).items;
  const tls = keys.find((k: { id: string; format: string }) => k.id === "tls" && k.format === "https://tinfoil.sh/key/spki-fp-sha256/v1");
  const hpke = keys.find((k: { id: string; format: string }) => k.id === "hpke" && k.format === "https://tinfoil.sh/key/x25519-hpke/v1");
  requireCondition(/^[a-f0-9]{64}$/.test(tls?.data ?? "") && /^[a-f0-9]{64}$/.test(hpke?.data ?? ""), "TEE_ATTESTATION_REJECTED");
  return { tls: tls.data, hpke: hpke.data };
}
