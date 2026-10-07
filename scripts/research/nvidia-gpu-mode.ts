import { parseHopperGpuMode } from "../../packages/tinfoil/src/gpu-mode.js";

// This CLI interprets fields, without authenticating signatures or a CPU session.
// The inference appraisal separately calls the same parser only after NVIDIA
// verifies the exact report bytes. Never use this output as device admission.
try {
  if (process.argv.length !== 2) throw Error();
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    const bytes = Buffer.from(chunk); length += bytes.length;
    if (length > 32 * 1024) throw Error();
    chunks.push(bytes);
  }
  const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).length !== 1 || typeof input.report !== "string") throw Error();
  console.log(JSON.stringify({ mode: parseHopperGpuMode(input.report), gpuSignatureVerified: false, inferenceQualified: false }));
} catch {
  console.log(JSON.stringify({ failure: "TEE_GPU_MODE_REJECTED", gpuSignatureVerified: false, inferenceQualified: false }));
  process.exitCode = 1;
}
