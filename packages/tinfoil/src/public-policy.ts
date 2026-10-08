import { createHash } from "node:crypto";
import { GPU_VERIFIER_QUALIFIED, INTEL_CANDIDATE, NVAT_HASHES, PUBLIC_BUILD_VERIFIER_SHA256 } from "./intel-appraisal.js";
import { GPU_VERSION_FLOORS } from "./gpu-policy.js";

// Authority/rule identity, not a catalog of deployment digests. The local
// installation's executable/dependency inventory remains a separate contract.
const authorityPolicy = {
  version: 1,
  profile: "tinfoil-gemma-single-gpu-public-v1",
  model: INTEL_CANDIDATE.model,
  host: INTEL_CANDIDATE.host,
  cpu: { type: "intel-tdx", root: "267a851c8d10982685b5f219d9ac2600ba71463569a6541827c2dc9fe9d6d699",
    status: "UpToDate", attributes: "0000001000000000", svnFloor: "03010200000000000000000000000000", collateralFloor: 20 },
  sigstoreRoot: "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
  issuer: "https://token.actions.githubusercontent.com",
  publicHostedWorkflows: [
    "tinfoilsh/confidential-gemma4-31b/.github/workflows/tinfoil-release-publish.yml@refs/tags/vMAJOR.MINOR.PATCH",
    "tinfoilsh/cvmimage/.github/workflows/release.yml@refs/tags/vMAJOR.MINOR.PATCH",
    "tinfoilsh/platform-endorsements/.github/workflows/build.yml@refs/tags/vMAJOR.MINOR.PATCH",
    "tinfoilsh/freshness-witness/.github/workflows/freshness.yml@refs/heads/main",
  ],
  freshness: { maxAgeMs: 7 * 86400000, futureSkewMs: 300000, sessionHoldMs: 60000, challengeLifetimeMs: 300000 },
  gpu: { architecture: "HOPPER", model: "GH100 A01 GSP BROM", count: 1, mode: "SPT", secureBoot: true, debug: "disabled",
    deviceRoot: "102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48",
    referenceRoot: "12977b5115acb0381179279fffeb5a8c4d264971ebb32298023a465fa41df5d1",
    versionFloors: GPU_VERSION_FLOORS, signedReferences: true, nonceMatchingOcsp: true },
  localArtifacts: { helper: PUBLIC_BUILD_VERIFIER_SHA256, nvat: NVAT_HASHES, image: INTEL_CANDIDATE.gpuImage },
  runtime: "gemma-single-gpu-v1",
  softwareContract: "public publishers preserve private per-boot keys, immutable runtime/model roots, closed engine egress and the NVIDIA protected channel/reset contract",
  transport: { tls: "TLS1.3-SPKI", body: "EHBP", sends: 1, rotation: "reject", cache: "fresh-encrypted-cache_salt" },
};

export const PUBLIC_BUILD_PROFILE_ID = authorityPolicy.profile;
export const PUBLIC_BUILD_AUTHORITY_POLICY_DIGEST = createHash("sha256").update(JSON.stringify(authorityPolicy)).digest("hex");

// Paused until the replacement GPU verifier is integrated, reviewed and
// qualified. Deliberately not configurable by environment.
export const PUBLIC_BUILD_PROFILE_ENABLED = GPU_VERIFIER_QUALIFIED;
