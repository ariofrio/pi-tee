import { parseHopperGpuMode } from "../../packages/tinfoil/src/gpu-mode.js";
import { gpuVersionsAllowed } from "../../packages/tinfoil/src/gpu-policy.js";

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
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some(key => key !== "report" && key !== "versions") || typeof input.report !== "string") throw Error();
  let versionPolicyCompatible: boolean | undefined;
  if (input.versions !== undefined) {
    const v = input.versions;
    if (!v || typeof v !== "object" || Array.isArray(v) || Object.keys(v).length !== 3 || !Object.hasOwn(v, "driver") || !Object.hasOwn(v, "vbios") || !Object.hasOwn(v, "hwmodel")) throw Error();
    versionPolicyCompatible = gpuVersionsAllowed(v.hwmodel, v.driver, v.vbios);
  }
  console.log(JSON.stringify({ mode: parseHopperGpuMode(input.report), ...(versionPolicyCompatible !== undefined ? { versionPolicyCompatible } : {}), gpuSignatureVerified: false, inferenceQualified: false }));
} catch {
  console.log(JSON.stringify({ failure: "TEE_GPU_MODE_REJECTED", gpuSignatureVerified: false, inferenceQualified: false }));
  process.exitCode = 1;
}
