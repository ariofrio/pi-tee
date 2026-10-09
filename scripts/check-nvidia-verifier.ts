import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { readBoundedBody } from "../packages/core/src/transport.js";
import { discoverTinfoilWorkers } from "../packages/tinfoil/src/worker-discovery.js";
import { gpuVersionsAllowed } from "../packages/tinfoil/src/gpu-policy.js";
import { parseHopperGpuMode } from "../packages/core/src/gpu-mode.js";
import { runNvidiaVerifier } from "../packages/core/src/nvidia-verifier.js";
import { collateralOracle, RIM_LAYOUT_CODES } from "./research/nvidia-collateral.js";

// GPU verifier seam only: no CPU/workload appraisal, credentials or inference.
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
    assert.equal(gpuVersionsAllowed(c.hwmodel, c["x-nvidia-gpu-driver-version"], c["x-nvidia-gpu-vbios-version"]), true);
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
  if (process.env.PI_TEE_NVIDIA_TEST_EVIDENCE) return JSON.parse(await readFile(process.env.PI_TEE_NVIDIA_TEST_EVIDENCE, "utf8"));
  const signal = AbortSignal.timeout(120000);
  const candidates = await discoverTinfoilWorkers({ model: "gemma4-31b", repository: "tinfoilsh/confidential-gemma4-31b", signal });
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
// A loopback HTTP proxy that refuses and counts every request routed to it.
async function refusingProxy() {
  let requests = 0;
  const server = createServer((_request, response) => { requests++; response.writeHead(502); response.end(); });
  server.on("connect", (_request, socket) => { requests++; socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"); });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return { url: `http://127.0.0.1:${address.port}`, requests: () => requests, close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()); }) };
}
let phase = "fixture";
async function attest(evidence: unknown, nonce: string, collateralOrigin?: string) {
  const checked = await runNvidiaVerifier({ evidence: [evidence], nonce, signal: AbortSignal.timeout(120000), collateralOrigin });
  let result: any;
  try { result = JSON.parse(checked.stdout); } catch { result = {}; }
  return { code: checked.code, result };
}
try {
  const { nonce, evidence } = await fixture();
  if (process.argv.includes("--save-evidence")) {
    await mkdir(".scratch/work/nvidia-diagnostics", { recursive: true, mode: 0o700 });
    await writeFile(".scratch/work/nvidia-diagnostics/fixture.json", JSON.stringify({ nonce, evidence }), { mode: 0o600 });
  }
  const damaged = structuredClone(evidence), bytes = Buffer.from(damaged.evidence, "base64");
  bytes[bytes.length - 1]! ^= 1; damaged.evidence = bytes.toString("base64");
  for (const [label, raw, challenge, expectedCode] of [
    ["authentic", evidence, nonce, 0], ["wrong-nonce", evidence, "00".repeat(32), 504],
    ["report-signature", damaged, nonce, 508], ["signed-mode", changedMode(evidence), nonce, 508], ["certificate-signature", changedCertificate(evidence), nonce, 802],
  ] as const) {
    phase = label;
    const { code, result } = await attest(raw, challenge);
    assert.equal(result.result_code, expectedCode);
    assert.equal(code === 0, expectedCode === 0);
    assert.equal(accepted(result, challenge, raw), expectedCode === 0);
    console.log(JSON.stringify({ case: label, accepted: expectedCode === 0, resultCode: result.result_code, inferenceRequests: 0, cpuVerified: false, workloadQualified: false }));
  }
  if (process.argv.includes("--collateral")) {
    const expectedCodes = { "rim-signature": 105, "ocsp-signature": 12, ...RIM_LAYOUT_CODES };
    for (const mode of ["authentic", ...Object.keys(expectedCodes) as (keyof typeof expectedCodes)[]] as const) {
      phase = `collateral-${mode}`;
      const oracle = await collateralOracle(mode);
      try {
        const { code, result } = await attest(evidence, nonce, oracle.origin);
        const observations = oracle.observations();
        assert.equal(observations.failures, 0); assert.ok(observations.deliveries > 0);
        if (mode === "authentic") {
          assert.equal(code, 0); assert.equal(accepted(result, nonce, evidence), true); assert.equal(observations.mutations, 0);
        } else {
          assert.notEqual(code, 0); assert.equal(accepted(result, nonce, evidence), false); assert.ok(observations.mutations > 0);
          assert.equal(result.result_code, expectedCodes[mode]);
          if (mode === "ocsp-signature") {
            assert.ok(result.claims?.some((claim: any) => ["x-nvidia-gpu-attestation-report-cert-chain", "x-nvidia-gpu-driver-rim-cert-chain", "x-nvidia-gpu-vbios-rim-cert-chain"].some(name => claim[name]?.["x-nvidia-cert-ocsp-response-valid"] === false)));
          }
        }
        console.log(JSON.stringify({ case: phase, accepted: mode === "authentic", resultCode: result.result_code, ...observations, inferenceRequests: 0, cpuVerified: false, workloadQualified: false }));
      } finally { await oracle.close(); }
    }
    // Node must not route the bridge through proxy settings, which it reads at
    // startup. Bun applies HTTP(S)_PROXY to fetch; its TLS still ends at NVIDIA.
    phase = "collateral-proxy-environment";
    if (process.versions.bun) console.log(JSON.stringify({ case: phase, skipped: "Bun applies proxy variables to fetch" }));
    else {
      const [oracle, proxy] = await Promise.all([collateralOracle("authentic"), refusingProxy()]);
      try {
        const child = spawn(process.execPath, [...process.execArgv, "scripts/research/nvidia-verifier-child.ts"], {
          env: { ...process.env, NODE_USE_ENV_PROXY: "1", HTTP_PROXY: proxy.url, HTTPS_PROXY: proxy.url, NO_PROXY: "" }, stdio: ["pipe", "pipe", "ignore"],
        });
        child.stdin.end(JSON.stringify({ evidence, nonce, collateralOrigin: oracle.origin }));
        let stdout = "";
        for await (const chunk of child.stdout) stdout += chunk;
        let result: any;
        try { result = JSON.parse(stdout); } catch { result = {}; }
        assert.equal(proxy.requests(), 0); assert.equal(accepted(result, nonce, evidence), true);
        console.log(JSON.stringify({ case: phase, accepted: true, resultCode: result.result_code, proxyRequests: proxy.requests(), ...oracle.observations(), inferenceRequests: 0 }));
      } finally { await Promise.all([oracle.close(), proxy.close()]); }
    }
  }
} catch {
  console.error(`NVIDIA verifier check failed at ${phase}. No inference was sent.`);
  process.exitCode = 1;
}
