import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { readBoundedBody } from "../packages/core/src/transport.js";
import { discoverTinfoilWorkers } from "../packages/tinfoil/src/worker-discovery.js";
import { gpuVersionsAllowed } from "../packages/tinfoil/src/gpu-policy.js";
import { parseHopperGpuMode } from "../packages/tinfoil/src/gpu-mode.js";
import { INTEL_CANDIDATE } from "../packages/tinfoil/src/intel-appraisal.js";

// GPU verifier seam only: no CPU/workload appraisal, credentials or inference.
const binary = resolve(process.env.PI_TEE_NATIVE_NVIDIA_BINARY ?? `.scratch/work/nvidia-native/artifact/bin/${process.platform === "win32" ? "nvattest.exe" : "nvattest"}`);
const execute = promisify(execFile);
const required = [
  "x-nvidia-gpu-arch-check", "x-nvidia-gpu-attestation-report-parsed", "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
  "x-nvidia-gpu-driver-rim-fetched", "x-nvidia-gpu-driver-rim-measurements-available", "x-nvidia-gpu-driver-rim-signature-verified", "x-nvidia-gpu-driver-rim-version-match",
  "x-nvidia-gpu-vbios-rim-fetched", "x-nvidia-gpu-vbios-rim-measurements-available", "x-nvidia-gpu-vbios-rim-signature-verified", "x-nvidia-gpu-vbios-rim-version-match", "x-nvidia-gpu-vbios-index-no-conflict",
  "x-nvidia-gpu-attestation-report-signature-verified", "x-nvidia-gpu-attestation-report-nonce-match",
];
function accepted(result: any, nonce: string, evidence: any): boolean {
  try {
    assert.equal(result.result_code, 0); assert.equal(result.claims.length, 1);
    const c = result.claims[0];
    assert.equal(c.eat_nonce, nonce); assert.equal(c.hwmodel, "GH100 A01 GSP BROM");
    assert.equal(c.measres, "success"); assert.equal(c.dbgstat, "disabled"); assert.equal(c.secboot, true);
    assert.equal(gpuVersionsAllowed(c["x-nvidia-gpu-driver-version"], c["x-nvidia-gpu-vbios-version"], "public-builds"), true);
    for (const name of required) assert.equal(c[name], true);
    for (const name of ["x-nvidia-gpu-attestation-report-cert-chain", "x-nvidia-gpu-driver-rim-cert-chain", "x-nvidia-gpu-vbios-rim-cert-chain"]) {
      const chain = c[name];
      assert.equal(chain["x-nvidia-cert-status"], "valid"); assert.equal(chain["x-nvidia-cert-ocsp-status"], "good");
      assert.equal(chain["x-nvidia-cert-ocsp-response-valid"], true); assert.equal(chain["x-nvidia-cert-ocsp-nonce-matches"], true);
    }
    assert.equal(parseHopperGpuMode(evidence.evidence), "spt");
    return true;
  } catch { return false; }
}
async function fixture() {
  if (process.env.PI_TEE_NATIVE_NVIDIA_TEST_EVIDENCE) return JSON.parse(await readFile(process.env.PI_TEE_NATIVE_NVIDIA_TEST_EVIDENCE, "utf8"));
  const signal = AbortSignal.timeout(120000);
  const candidates = await discoverTinfoilWorkers({ model: "gemma4-31b", repository: "tinfoilsh/confidential-gemma4-31b", signal });
  candidates.sort((a, b) => Number(b.host === INTEL_CANDIDATE.host) - Number(a.host === INTEL_CANDIDATE.host));
  // Test every candidate until one usable fresh Hopper report is obtained.
  // A complete lack of evidence fails this live check rather than skipping it.
  for (let offset = 0; offset < candidates.length; offset += 4) {
    const attempts = await Promise.allSettled(candidates.slice(offset, offset + 4).map(async ({ host }) => {
      const nonce = randomBytes(32).toString("hex");
      const attempt = AbortSignal.any([signal, AbortSignal.timeout(10000)]);
      const response = await fetch(`https://${host}/.well-known/tinfoil-attestation?nonce=${nonce}`, { signal: attempt, redirect: "error" });
      if (!response.ok) throw Error();
      const envelope = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(response.body, 2 * 1024 * 1024, attempt)));
      const devices = JSON.parse(Buffer.from(envelope.device_evidence, "base64").toString("utf8"));
      const item = devices.items?.[0];
      if (devices.items?.length !== 1 || item?.vendor !== "nvidia" || item?.kind !== "gpu" || item?.format !== "https://tinfoil.sh/format/nvidia-gpu-evidence/v1" ||
          item.evidence?.arch !== "HOPPER" || item.evidence?.nonce !== nonce || parseHopperGpuMode(item.evidence.evidence) !== "spt") throw Error();
      return { nonce, evidence: item.evidence };
    }));
    const usable = attempts.find(result => result.status === "fulfilled");
    if (usable?.status === "fulfilled") return usable.value;
    signal.throwIfAborted();
  }
  throw Error("No fresh GPU fixture");
}
function changedMode(evidence: any) {
  const copy = structuredClone(evidence), bytes = Buffer.from(copy.evidence, "base64");
  let offset = 37 + 8 + bytes.readUIntLE(42, 3) + 32;
  const end = offset + 2 + bytes.readUInt16LE(offset); offset += 2;
  while (offset < end) {
    const tag = bytes.readUInt16LE(offset), length = bytes.readUInt16LE(offset + 2); offset += 4;
    if (tag === 36) {
      bytes.fill(0, offset, offset + length); bytes[offset] = 1;
      copy.evidence = bytes.toString("base64");
      assert.equal(parseHopperGpuMode(copy.evidence), "mpt");
      return copy;
    }
    offset += length;
  }
  throw Error("Missing signed GPU mode");
}
function changedCertificate(evidence: any) {
  let changed = false;
  const pem = Buffer.from(evidence.certificate, "base64").toString("utf8");
  const certificate = pem.replace(/-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n]+?)\s*-----END CERTIFICATE-----/, (_match: string, encoded: string) => {
    const der = Buffer.from(encoded, "base64");
    assert.ok(der.length > 100);
    der[der.length - 1]! ^= 1;
    changed = true;
    return `-----BEGIN CERTIFICATE-----\n${der.toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----`;
  });
  assert.equal(changed, true);
  return { ...evidence, certificate: Buffer.from(certificate).toString("base64") };
}
await mkdir(".scratch/work", { recursive: true });
const scratch = await mkdtemp(resolve(".scratch/work/native-nvidia-check-"));
let phase = "fixture";
try {
  const { nonce, evidence } = await fixture();
  if (process.argv.includes("--save-evidence")) {
    await mkdir(".scratch/work/native-nvidia-diagnostics", { recursive: true, mode: 0o700 });
    await writeFile(".scratch/work/native-nvidia-diagnostics/fixture.json", JSON.stringify({ nonce, evidence }), { mode: 0o600 });
  }
  const damaged = structuredClone(evidence), bytes = Buffer.from(damaged.evidence, "base64");
  bytes[bytes.length - 1]! ^= 1; damaged.evidence = bytes.toString("base64");
  for (const [label, raw, challenge, expectedCode] of [
    ["authentic", evidence, nonce, 0], ["wrong-nonce", evidence, "00".repeat(32), 504],
    ["report-signature", damaged, nonce, 508], ["signed-mode", changedMode(evidence), nonce, 508], ["certificate-signature", changedCertificate(evidence), nonce, 802],
  ] as const) {
    phase = label;
    const file = resolve(scratch, `${label}.json`);
    await writeFile(file, JSON.stringify([raw]), { mode: 0o600, flag: "wx" });
    let stdout = "", code: string | number = 0;
    try {
      ({ stdout } = await execute(binary, ["--log-level", "off", "--format", "json", "attest", "--device", "gpu", "--gpu-evidence-source", "file", "--gpu-evidence-file", file, "--verifier", "local", "--nonce", challenge], {
        timeout: 90000, maxBuffer: 256 * 1024, env: { PATH: process.env.PATH, ...(process.platform === "win32" ? { SystemRoot: process.env.SystemRoot } : {}) },
      }));
    } catch (error: any) { code = error.code ?? "process-failed"; stdout = error.stdout ?? ""; }
    let result: any;
    try { result = JSON.parse(stdout); } catch { result = {}; }
    if (process.argv.includes("--save-evidence")) await writeFile(`.scratch/work/native-nvidia-diagnostics/${label}.json`, stdout, { mode: 0o600 });
    assert.equal(result.result_code, expectedCode);
    assert.equal(code === 0, expectedCode === 0);
    assert.equal(accepted(result, challenge, raw), expectedCode === 0);
    console.log(JSON.stringify({ case: label, accepted: expectedCode === 0, resultCode: result.result_code, inferenceRequests: 0, cpuVerified: false, workloadQualified: false }));
  }
} catch {
  console.error(`Native GPU candidate check failed at ${phase}. No inference was sent.`);
  process.exitCode = 1;
} finally { await rm(scratch, { recursive: true, force: true, maxRetries: 4, retryDelay: 250 }); }
