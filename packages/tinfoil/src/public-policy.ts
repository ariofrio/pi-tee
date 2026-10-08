import { createHash } from "node:crypto";
import { GPU_POLICIES } from "./gpu-policy.js";
import { SNP_FIRMWARE } from "./snp-measurement.js";
import { WASM_ARTIFACTS } from "./wasm-artifacts.js";
import { CERTIFICATE_CHAINS, PUBLIC_MODELS, REQUIRED_CLAIMS, WORKER_HOST } from "./worker-appraisal.js";

// Authority/rule identity, not a catalog of deployment digests. The local
// installation's executable/dependency inventory remains a separate contract.
const authorityPolicy = {
  version: 2,
  profile: "tinfoil-public-builds-v2",
  models: PUBLIC_MODELS,
  // Discovery is untrusted; any host in this namespace is appraised freshly.
  workerHosts: WORKER_HOST.source,
  cpu: {
    tdx: { root: "267a851c8d10982685b5f219d9ac2600ba71463569a6541827c2dc9fe9d6d699",
      status: "UpToDate", attributes: "0000001000000000", svnFloor: "03010200000000000000000000000000", collateralFloor: 20 },
    sevSnp: { arks: { genoa: "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1", turin: "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a" },
      revocation: "AMD CRL", tcbFloors: "platform publisher, raised to local per-CPU floors",
      // AMD-SB-3019/3020/3027, keyed on the report's CPUID family/model/stepping.
      localFloors: {
        "19/11/01 Genoa": { build: 21, api: "1.55", tcb: "bl7/tee0/snp1b/ucode56" },
        "19/11/02 Genoa-X": { build: 21, api: "1.55", tcb: "bl7/tee0/snp1b/ucode51" },
        "1a/02/01 Turin": { build: 0, api: "1.58", tcb: "fmc1/bl1/tee1/snp04/ucode51" },
      },
      firmware: SNP_FIRMWARE,
      guest: { debug: false, migrateMA: false, vmpl: 0, provisionalFirmware: false } },
    machinePolicies: "*-prod only",
  },
  sigstoreRoot: "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
  issuer: "https://token.actions.githubusercontent.com",
  publicHostedWorkflows: [
    ...Object.values(PUBLIC_MODELS).map(repo => `${repo}/.github/workflows/tinfoil-release-publish.yml@refs/tags/vMAJOR.MINOR.PATCH`),
    "tinfoilsh/cvmimage/.github/workflows/release.yml@refs/tags/vMAJOR.MINOR.PATCH",
    "tinfoilsh/platform-endorsements/.github/workflows/build.yml@refs/tags/vMAJOR.MINOR.PATCH",
    "tinfoilsh/freshness-witness/.github/workflows/freshness.yml@refs/heads/main",
  ],
  freshness: { maxAgeMs: 7 * 86400000, futureSkewMs: 300000, sessionHoldMs: 60000, challengeLifetimeMs: 300000,
    expiry: "min(checked + sessionHold, challenge + challengeLifetime, codeFreshness + maxAge, platformFreshness + maxAge)" },
  gpu: { models: GPU_POLICIES, modes: { single: "SPT", multi: "MPT" }, secureBoot: true, debug: "disabled", distinctDevices: true,
    deviceRoot: "102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48",
    referenceRoot: "12977b5115acb0381179279fffeb5a8c4d264971ebb32298023a465fa41df5d1",
    signedReferences: "certificate-chain leaf", nonceMatchingOcsp: true,
    requiredClaims: REQUIRED_CLAIMS, certificateChains: CERTIFICATE_CHAINS },
  localArtifacts: WASM_ARTIFACTS,
  runtime: "tinfoil-vllm-v1",
  engineEntrypoints: ["vllm serve", "/opt/tinfoil/inference-sidecar vllm serve"],
  softwareContract: "public publishers preserve private per-boot keys, immutable runtime/model roots, closed engine egress and the NVIDIA protected channel/reset contract",
  transport: { tls: "TLS1.3-SPKI", body: "EHBP", sends: 1, rotation: "reject", cache: "fresh-encrypted-cache_salt" },
};

export const PUBLIC_BUILD_PROFILE_ID = authorityPolicy.profile;
export const PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST = createHash("sha256").update(JSON.stringify(authorityPolicy)).digest("hex");

// Enabled after independent review of the WebAssembly verifiers, the NVIDIA
// reference-manifest patch, the TLS client and the multi-model/SEV-SNP
// profile. Deliberately not configurable by environment.
export const PUBLIC_BUILD_PROFILE_ENABLED = true;
