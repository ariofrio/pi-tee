import { runNvidiaVerifier } from "../../packages/core/src/nvidia-verifier.js";

// Runs one NVIDIA appraisal in a fresh process, so a check controls settings
// that Node reads only at startup. Input: { evidence, nonce, collateralOrigin }.
const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const { evidence, nonce, collateralOrigin } = JSON.parse(Buffer.concat(chunks).toString("utf8"));
const { stdout } = await runNvidiaVerifier({ evidence: [evidence], nonce, signal: AbortSignal.timeout(120000), collateralOrigin });
process.stdout.write(stdout);
