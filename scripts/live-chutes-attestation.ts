import { parsePolicy } from "pi-tee-core";
import { CHUTES_BASE_URL, parseChutesCatalog } from "../packages/chutes/src/catalog.js";
import { openChutesTransport } from "../packages/chutes/src/transport.js";

// Discovery credentials are scoped to this command; no inference or invocation tokens are logged.
const apiKey = process.env.CHUTES_API_KEY;
if (!apiKey) throw new Error("Set CHUTES_API_KEY in this command's environment.");
const policy = parsePolicy(process.env.PI_TEE_POLICY ?? "trust-provider-and-host,host=current");
const signal = AbortSignal.timeout(180000);
const response = await fetch(`${CHUTES_BASE_URL}/models`, { signal, redirect: "error" });
if (!response.ok) throw new Error("Chutes catalog unavailable.");
const models = parseChutesCatalog(await response.json()).filter(model => process.argv.length <= 2 || process.argv.slice(2).includes(model.id));
for (const model of models) {
  try {
    const session = await openChutesTransport(apiKey, model.id, signal, policy);
    const { code, host, gpu, egress, observed } = session.security;
    session.dispose?.();
    console.log(JSON.stringify({ model: model.id, time: new Date().toISOString(), levels: { A: code, H: host, G: gpu, X: egress }, observed, inference: false }));
  } catch (error) {
    console.log(JSON.stringify({ model: model.id, time: new Date().toISOString(), admitted: false,
      reason: error instanceof Error && /^TEE_[A-Z_]+$/.test(error.message) ? error.message : "TEE_ATTESTATION_REJECTED", inference: false }));
    process.exitCode = 1;
  }
}
