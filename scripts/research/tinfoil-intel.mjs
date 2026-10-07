// Fixed Intel research candidate. No production Approved decision or automatic helper download.
// Default: fresh CPU + GPU appraisal. --infer adds one capped synthetic encrypted request.
import { randomBytes, createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Identity } from "ehbp";
import { pinnedTlsFetch, readBoundedBody, limitResponseBody, MAX_ENCRYPTED_RESPONSE_BYTES, MAX_RESPONSE_BYTES } from "../../packages/core/dist/index.js";
import { parseHopperGpuMode } from "../../packages/tinfoil/dist/gpu-mode.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const host = "gemma4-31b-inf8-0.tinfoil.containers.tinfoil.dev";
const image = "sha256:7648914f1e3bc8c23e208247c93551391f2c121674ef99a1dfc7106311d8f707";
const bundle = resolve(root, "../work/nvat-gpu/libnvat-linux-sbsa-1.2.2.1780962352-archive");
const hashes = {
  "bin/nvattest": "0db6cba463aefa91a1a81c62bc8b3928ffe5c3d8347bde6561f5ea08dab156ae",
  "lib/libnvat.so.1.2.2": "b87d4bf93dfd0f1ffd8999d7d04db3e6a44c4048ae9b8e319f2f1cab2d885776",
  "lib/libnvat.so.1": "b87d4bf93dfd0f1ffd8999d7d04db3e6a44c4048ae9b8e319f2f1cab2d885776",
  "lib/libnvat.so": "b87d4bf93dfd0f1ffd8999d7d04db3e6a44c4048ae9b8e319f2f1cab2d885776",
};
const policySha256 = "6eacea241bd6ac37901cc3cb738f62eebb513e827d28023ffdfde719d54960b2";
const infer = process.argv.includes("--infer");
const negatives = process.argv.includes("--test-negatives");
if (process.argv.slice(2).some(arg => !["--infer", "--test-negatives"].includes(arg))) throw Error("Use --infer and/or --test-negatives.");
const deadline = AbortSignal.timeout(180000);
const summary = { host, checkedAt: new Date().toISOString(), independentApproval: false, inferenceRequests: 0, runtimeProviderReferenceAuthority: false };
let scratch;
function requireCondition(ok, code) { if (!ok) throw Error(code); }
function command(file, args, { input, env = { PATH: process.env.PATH, HOME: process.env.HOME }, maxBuffer = 128 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, { env, signal: deadline, timeout: 60000, maxBuffer }, (error, stdout) => {
      if (error && typeof error.code !== "number") return reject(Error("TEE_VERIFIER_PROCESS_REJECTED"));
      resolve({ code: error?.code ?? 0, stdout });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}
async function cpu(input) {
  const result = await command(resolve(root, ".scratch/work/tinfoil-cpu-verifier"), [], { input: JSON.stringify(input), env: { TZ: "UTC" }, maxBuffer: 4096 });
  const verdict = JSON.parse(result.stdout);
  requireCondition(result.code === 0 && verdict.cpuVerified === true && verdict.policySha256 === policySha256 && verdict.independentApproval === false && verdict.runtimeProviderReferenceAuthority === false, "TEE_CPU_POLICY_REJECTED");
  return verdict;
}
async function gpu(evidence, nonce, label) {
  const path = resolve(scratch, `${label}.json`);
  await writeFile(path, JSON.stringify(evidence), { mode: 0o600, flag: "wx" });
  const name = `pi-tee-gpu-${randomBytes(8).toString("hex")}`;
  let result;
  try {
    result = await command("docker", ["run", "--rm", "--pull=never", "--name", name, "--cpus=2", "--memory=1g", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--mount", `type=bind,source=${bundle},target=/evidence/libnvat-linux-sbsa-1.2.2.1780962352-archive,readonly`, "--mount", `type=bind,source=${scratch},target=/fixtures,readonly`, image, "--log-level", "off", "--format", "json", "attest", "--device", "gpu", "--gpu-evidence-source", "file", "--gpu-evidence-file", `/fixtures/${label}.json`, "--verifier", "local", "--nonce", nonce]);
  } finally {
    // Killing the CLI alone does not establish that its container stopped.
    await new Promise(resolve => execFile("docker", ["rm", "--force", name], { timeout: 10000, maxBuffer: 4096, env: { PATH: process.env.PATH, HOME: process.env.HOME } }, () => resolve()));
  }
  const verdict = JSON.parse(result.stdout);
  if (result.code !== 0 || verdict.result_code !== 0) return { accepted: false, verifierResult: verdict.result_code };
  requireCondition(Array.isArray(verdict.claims) && verdict.claims.length === 1, "TEE_GPU_POLICY_REJECTED");
  const c = verdict.claims[0];
  requireCondition(c.eat_nonce === nonce && c.hwmodel === "GH100 A01 GSP BROM" && c.measres === "success" && c.dbgstat === "disabled" && c.secboot === true &&
    c["x-nvidia-gpu-driver-version"] === "595.71.05" && c["x-nvidia-gpu-vbios-version"] === "96.00.D9.00.02" &&
    c["x-nvidia-gpu-attestation-report-signature-verified"] === true && c["x-nvidia-gpu-attestation-report-nonce-match"] === true, "TEE_GPU_POLICY_REJECTED");
  for (const field of ["x-nvidia-gpu-arch-check", "x-nvidia-gpu-attestation-report-parsed", "x-nvidia-gpu-attestation-report-cert-chain-fwid-match", "x-nvidia-gpu-driver-rim-fetched", "x-nvidia-gpu-driver-rim-measurements-available", "x-nvidia-gpu-driver-rim-signature-verified", "x-nvidia-gpu-driver-rim-version-match", "x-nvidia-gpu-vbios-rim-fetched", "x-nvidia-gpu-vbios-rim-measurements-available", "x-nvidia-gpu-vbios-rim-signature-verified", "x-nvidia-gpu-vbios-rim-version-match", "x-nvidia-gpu-vbios-index-no-conflict"]) {
    requireCondition(c[field] === true, "TEE_GPU_POLICY_REJECTED");
  }
  for (const field of ["x-nvidia-gpu-attestation-report-cert-chain", "x-nvidia-gpu-driver-rim-cert-chain", "x-nvidia-gpu-vbios-rim-cert-chain"]) {
    const chain = c[field];
    requireCondition(chain?.["x-nvidia-cert-status"] === "valid" && chain["x-nvidia-cert-ocsp-status"] === "good" && chain["x-nvidia-cert-ocsp-response-valid"] === true && chain["x-nvidia-cert-ocsp-nonce-matches"] === true, "TEE_GPU_POLICY_REJECTED");
  }
  return { accepted: true };
}
try {
  requireCondition(createHash("sha256").update(await readFile(resolve(root, ".scratch/work/tinfoil-cpu-verifier"))).digest("hex") === "bcfc1896c156727a7612f4ff7500993236cd648f10e0a63e46eb2f71a3d03316", "TEE_VERIFIER_ARTIFACT_REJECTED");
  for (const [path, hash] of Object.entries(hashes)) requireCondition(createHash("sha256").update(await readFile(resolve(bundle, path))).digest("hex") === hash, "TEE_VERIFIER_ARTIFACT_REJECTED");
  await mkdir(resolve(root, ".scratch/work"), { recursive: true });
  scratch = await mkdtemp(resolve(root, ".scratch/work/intel-session-"));
  const nonce = randomBytes(32).toString("hex");
  const response = await fetch(`https://${host}/.well-known/tinfoil-attestation?nonce=${nonce}`, { signal: deadline, redirect: "error" });
  requireCondition(response.ok, "TEE_EVIDENCE_FETCH_REJECTED");
  const bytes = await readBoundedBody(response.body, 2 * 1024 * 1024, deadline);
  const envelope = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  await cpu({ nonce, envelope });
  summary.cpuVerified = true;
  summary.policySha256 = policySha256;
  summary.httpEnvelopeSha256 = createHash("sha256").update(bytes).digest("hex");
  // Only use sections after the strict Go parser authenticated their exact bytes.
  const devices = JSON.parse(Buffer.from(envelope.device_evidence, "base64").toString("utf8"));
  requireCondition(devices.items?.length === 1 && devices.items[0].id === "gpu0" && devices.items[0].kind === "gpu" && devices.items[0].vendor === "nvidia" && devices.items[0].format === "https://tinfoil.sh/format/nvidia-gpu-evidence/v1", "TEE_GPU_POLICY_REJECTED");
  const evidence = devices.items.map(item => item.evidence);
  requireCondition(evidence[0].nonce === nonce && evidence[0].arch === "HOPPER", "TEE_GPU_POLICY_REJECTED");
  requireCondition((await gpu(evidence, nonce, "authentic")).accepted, "TEE_GPU_POLICY_REJECTED");
  requireCondition(parseHopperGpuMode(evidence[0].evidence) === "spt", "TEE_GPU_MODE_REJECTED");
  summary.gpuVerified = true;
  summary.gpuMode = "spt";
  if (negatives) {
    const forged = structuredClone(evidence);
    const report = Buffer.from(forged[0].evidence, "base64");
    report[report.length - 1] ^= 1;
    forged[0].evidence = report.toString("base64");
    summary.forgedGpuRejected = !(await gpu(forged, nonce, "forged")).accepted;
    summary.wrongGpuNonceRejected = !(await gpu(evidence, "00".repeat(32), "nonce")).accepted;
    // Change only the signed feature field, retaining the real report format,
    // nonce, certificates and signature. Require NVIDIA's signature error,
    // not merely our mode guard, to establish that this field is authenticated.
    const changedMode = structuredClone(evidence);
    const modeReport = Buffer.from(changedMode[0].evidence, "base64");
    let offset = 37 + 8 + modeReport.readUIntLE(42, 3) + 32;
    const opaqueLength = modeReport.readUInt16LE(offset); offset += 2;
    const end = offset + opaqueLength;
    let changed = false;
    while (offset < end) {
      const type = modeReport.readUInt16LE(offset), length = modeReport.readUInt16LE(offset + 2);
      offset += 4;
      if (type === 36) { modeReport[offset] = 1; changed = true; break; }
      offset += length;
    }
    requireCondition(changed, "TEE_GPU_NEGATIVE_TEST_FAILED");
    changedMode[0].evidence = modeReport.toString("base64");
    const tampered = await gpu(changedMode, nonce, "mode");
    // NVAT_RC_GPU_EVIDENCE_INVALID_SIGNATURE in the pinned official nvat.h.
    summary.forgedGpuModeSignatureRejected = !tampered.accepted && tampered.verifierResult === 508;
    requireCondition(summary.forgedGpuRejected && summary.wrongGpuNonceRejected && summary.forgedGpuModeSignatureRejected, "TEE_GPU_NEGATIVE_TEST_FAILED");
  }
  if (infer) {
    requireCondition(process.env.TINFOIL_API_KEY, "TEE_API_KEY_REQUIRED");
    const keys = JSON.parse(Buffer.from(envelope.crypto_material, "base64").toString("utf8")).items;
    const tls = keys.find(k => k.id === "tls" && k.format === "https://tinfoil.sh/key/spki-fp-sha256/v1");
    const hpke = keys.find(k => k.id === "hpke" && k.format === "https://tinfoil.sh/key/x25519-hpke/v1");
    requireCondition(/^[a-f0-9]{64}$/.test(tls?.data ?? "") && /^[a-f0-9]{64}$/.test(hpke?.data ?? ""), "TEE_INFERENCE_KEYS_REJECTED");
    const endpoint = `https://${host}/v1/chat/completions`;
    const identity = await Identity.fromPublicKeyHex(hpke.data);
    const encrypted = await identity.encryptRequestWithContext(new Request(endpoint, {
      method: "POST", signal: deadline, headers: { authorization: `Bearer ${process.env.TINFOIL_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "gemma4-31b", messages: [{ role: "user", content: "Reply with exactly INTEL_DIRECT_OK." }], stream: true, stream_options: { include_usage: true }, max_tokens: 128, temperature: 0, chat_template_kwargs: { enable_thinking: false }, cache_salt: randomBytes(32).toString("hex") }),
    }));
    requireCondition(encrypted.context, "TEE_REQUEST_REJECTED");
    summary.inferenceRequests = 1;
    const wire = await pinnedTlsFetch(endpoint, tls.data)(encrypted.request);
    requireCondition(wire.status === 200, "TEE_RESPONSE_REJECTED");
    const plaintext = await identity.decryptResponseWithContext(limitResponseBody(wire, { signal: deadline, maxBytes: MAX_ENCRYPTED_RESPONSE_BYTES }), encrypted.context);
    const body = new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(plaintext.body, MAX_RESPONSE_BYTES, deadline));
    let content = ""; let usage = false; let finished = false;
    for (const line of body.split("\n")) {
      if (!line.startsWith("data: ") || line === "data: [DONE]") continue;
      const value = JSON.parse(line.slice(6));
      for (const c of value.choices ?? []) { content += c.delta?.content ?? ""; finished ||= c.finish_reason === "stop"; }
      usage ||= value.usage?.total_tokens > 0;
    }
    requireCondition(finished && body.includes("data: [DONE]") && content.includes("INTEL_DIRECT_OK") && usage, "TEE_RESPONSE_REJECTED");
    summary.encryptedInferenceVerified = true;
    summary.syntheticMarker = true;
    summary.usageReturned = true;
  }
} catch (error) {
  summary.failure = /^TEE_[A-Z_]+$/.test(error?.message ?? "") ? error.message : "TEE_QUALIFICATION_FAILED";
  process.exitCode = 1;
} finally { if (scratch) await rm(scratch, { recursive: true, force: true }); }
console.log(JSON.stringify(summary));
