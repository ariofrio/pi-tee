import { appraiseRouter, ROUTER_HOST } from "../packages/tinfoil/src/router.js";
import { parsePolicy } from "../packages/core/src/index.js";

const router = await appraiseRouter({ signal: AbortSignal.timeout(120_000), policy: parsePolicy("trust-provider-and-host") });
console.log(`PASS: ${ROUTER_HOST} passes pi-tee's fresh-nonce router appraisal (${router.security.observed[0]}). No inference or credentials involved.`);
