import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { SecureClient } from "tinfoil";
import { withAbort } from "../packages/core/src/transport.js";

const client = new SecureClient({ userCacheSecret: randomBytes(32).toString("hex"), transport: "ehbp" });
await withAbort(client.ready(), AbortSignal.timeout(30_000));
assert.equal(client.getVerificationDocument().securityVerified, true);
console.log("PASS: current Tinfoil router evidence passes SDK acceptance. No inference, credentials, or independent approval involved.");
