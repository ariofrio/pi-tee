import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { readBoundedBody, record } from "../packages/core/src/index.js";
import { discoverTinfoilWorkers } from "../packages/tinfoil/src/worker-discovery.js";

// Publisher routing anchors for the current Pi-compatible chat workloads.
// This probe discovers/collects evidence; it does not qualify these publishers or workers.
const repositories: Record<string, string> = {
  "deepseek-v4-1-flash": "tinfoilsh/confidential-deepseek-v4-1-flash",
  "glm-5-3": "tinfoilsh/confidential-glm5-3-nvfp4",
  "glm-5-3-flash": "tinfoilsh/confidential-glm5-3-flash",
  "kimi-k3": "tinfoilsh/confidential-kimi-k3",
  "llama3-3-70b": "tinfoilsh/confidential-llama3-3-70b",
  "gemma4-31b": "tinfoilsh/confidential-gemma4-31b",
  "gpt-oss-120b": "tinfoilsh/confidential-gpt-oss-120b",
};
const saveEvidence = process.argv.includes("--save-evidence");
if (process.argv.slice(2).some(arg => arg !== "--save-evidence")) throw new Error("Only --save-evidence is supported.");
const directory = resolve(".scratch/work/worker-discovery-evidence");
if (saveEvidence) await mkdir(directory, { recursive: true, mode: 0o700 });
const signal = AbortSignal.timeout(180000);
const groups = await Promise.all(Object.entries(repositories).map(async ([model, repository]) => ({
  model, repository, candidates: await discoverTinfoilWorkers({ model, repository, signal }).catch(() => {
    signal.throwIfAborted();
    console.log(JSON.stringify({ model, discovery: "unavailable", hardwareVerified: false, inferenceQualified: false }));
    return [];
  }),
})));
const candidates = groups.flatMap(group => group.candidates.map(candidate => ({ ...candidate, model: group.model })));
let next = 0;
const observations: Record<string, unknown>[] = [];
await Promise.all(Array.from({ length: Math.min(6, candidates.length) }, async () => {
  while (next < candidates.length) {
    signal.throwIfAborted();
    const candidate = candidates[next++]!;
    const nonce = randomBytes(32).toString("hex");
    const observation: Record<string, unknown> = { ...candidate, hardwareVerified: false, inferenceQualified: false };
    const url = new URL(`https://${candidate.host}/.well-known/tinfoil-attestation`);
    url.searchParams.set("nonce", nonce);
    try {
      const bound = AbortSignal.any([signal, AbortSignal.timeout(15000)]);
      const response = await fetch(url, { signal: bound, redirect: "error" });
      observation.status = response.status;
      const raw = new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(response.body, 2 * 1024 * 1024, bound));
      if (response.ok) {
        const envelope = record(JSON.parse(raw));
        observation.claimedCpuFormat = record(envelope.cpu_evidence).format;
        const devices = typeof envelope.device_evidence === "string"
          ? record(JSON.parse(Buffer.from(envelope.device_evidence, "base64").toString("utf8"))) : {};
        observation.claimedDeviceCount = Array.isArray(devices.items) ? devices.items.length : 0;
        if (saveEvidence) await writeFile(resolve(directory, `${candidate.host}.json`), JSON.stringify({ nonce, envelope }) + "\n", { mode: 0o600 });
      }
    } catch (error) {
      signal.throwIfAborted();
      observation.errorClass = error instanceof Error ? error.name : "Error";
      const code = record(record(error).cause).code;
      if (typeof code === "string" && /^[A-Z_]{1,60}$/.test(code)) observation.networkErrorCode = code;
    }
    observations.push(observation);
    console.log(JSON.stringify(observation));
  }
}));
console.log(JSON.stringify({ summary: { models: groups.length, candidates: candidates.length,
  evidenceResponses: observations.filter(item => item.status === 200).length,
  hardwareVerified: false, inferenceQualified: false }, privateEvidenceSaved: saveEvidence }));
