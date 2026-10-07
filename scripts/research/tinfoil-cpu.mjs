// Public CPU evidence only. No API key, inference or automatic helper download.
import { execFile } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const route = process.argv[2] ?? "intel";
if (!["intel", "amd"].includes(route) || process.argv.length > 4) throw new Error("Pass intel or amd, optionally followed by an evidence-output path.");
const host = route === "intel" ? "gemma4-31b-inf8-0.tinfoil.containers.tinfoil.dev" : "gemma4-31b-inf6-3.tinfoil.containers.tinfoil.dev";
const nonce = randomBytes(32).toString("hex");
const summary = { host, checkedAt: new Date().toISOString(), inferenceRequests: 0, independentApproval: false };
try {
  const response = await fetch(`https://${host}/.well-known/tinfoil-attestation?nonce=${nonce}`, {
    signal: AbortSignal.timeout(30000), redirect: "error",
  });
  summary.status = response.status;
  if (!response.ok) throw new Error("TEE_EVIDENCE_FETCH_REJECTED");
  const reader = response.body.getReader();
  const chunks = []; let size = 0;
  for (;;) {
    const { done, value } = await reader.read(); if (done) break;
    size += value.length;
    if (size > 2 * 1024 * 1024) { await reader.cancel(); throw new Error("TEE_EVIDENCE_INPUT_REJECTED"); }
    chunks.push(value);
  }
  const bytes = Buffer.concat(chunks);
  const envelope = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  const input = JSON.stringify({ nonce, envelope });
  summary.httpEnvelopeSha256 = createHash("sha256").update(bytes).digest("hex");
  if (process.argv[3]) {
    // Optional private fixture for the real-evidence negative tests; not a report.
    await writeFile(resolve(process.argv[3]), input, { mode: 0o600, flag: "wx" });
  }
  const verdict = await new Promise((accept, reject) => {
    const child = execFile(resolve(root, ".scratch/work/tinfoil-cpu-verifier"), [], {
      env: { TZ: "UTC" }, timeout: 30000, maxBuffer: 4096,
    }, (error, stdout) => {
      try {
        const value = JSON.parse(stdout);
        if (error && error.code !== 1) return reject(new Error("TEE_VERIFIER_PROCESS_REJECTED"));
        if (typeof value.cpuVerified !== "boolean" || value.independentApproval !== false) return reject(new Error("TEE_VERIFIER_PROCESS_REJECTED"));
        accept(value);
      } catch { reject(new Error("TEE_VERIFIER_PROCESS_REJECTED")); }
    });
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
  Object.assign(summary, verdict);
} catch (error) {
  summary.failure = /^TEE_[A-Z_]+$/.test(error?.message ?? "") ? error.message : "TEE_EVIDENCE_FETCH_REJECTED";
}
console.log(JSON.stringify(summary));
if (summary.cpuVerified !== true) process.exitCode = 1;
