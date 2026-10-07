import { randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import assert from "node:assert/strict";
import { readBoundedBody } from "pi-tee-core";
import { verifyPublicBuildArtifacts } from "../../packages/tinfoil/dist/public-build.js";

// Evidence and public artifacts only: no login, inference or key release.
const [helperPath, fixturePath] = process.argv.slice(2);
assert(helperPath && process.argv.length <= 4, "usage: node tinfoil-public-build.mjs HELPER [NEW_EVIDENCE_FILE]");
const signal = AbortSignal.timeout(240000);
const host = "gemma4-31b-inf8-0.tinfoil.containers.tinfoil.dev";
const nonce = randomBytes(32).toString("hex");
const response = await fetch(`https://${host}/.well-known/tinfoil-attestation?nonce=${nonce}`, { signal, redirect: "error" });
assert(response.ok && response.body, "TEE_ATTESTATION_REJECTED");
const raw = new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(response.body, 2 * 1024 * 1024, signal));
// Pass exact document bytes to the same artifact chain as the native candidate.
const verified = await verifyPublicBuildArtifacts({ helperPath: resolve(helperPath), raw, nonce, signal });
if (fixturePath) await writeFile(resolve(fixturePath), `{"nonce":${JSON.stringify(nonce)},"envelope":${raw}}`, { mode: 0o600, flag: "wx" });
console.log(JSON.stringify(verified));
