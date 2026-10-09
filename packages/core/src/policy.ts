export type PolicyMode = string;
export const POSITIONS = ["public-builds", "public-builds-trust-host", "trust-provider", "trust-provider-and-host"] as const;
export type Position = typeof POSITIONS[number];
export const POLICY_VALUES = {
  code: ["public-release", "fixed-private", "provider-controlled"],
  host: ["current", "outdated-firmware", "stale"],
  gpu: ["verified", "gaps", "unchecked"],
  egress: ["none", "metadata", "any"],
  build: ["reproduced-off-github", "reproduced", "publisher-workflow", "signed"],
  review: ["pinned", "window", "none"],
  verifier: ["local", "nras"],
} as const;
export type SecurityPolicy = Readonly<{
  position: Position;
  code: typeof POLICY_VALUES.code[number];
  host: typeof POLICY_VALUES.host[number];
  gpu: typeof POLICY_VALUES.gpu[number];
  egress: typeof POLICY_VALUES.egress[number];
  build?: typeof POLICY_VALUES.build[number];
  review?: typeof POLICY_VALUES.review[number];
  verifier: typeof POLICY_VALUES.verifier[number];
  warnings: readonly string[];
}>;
export const DEFAULT_POLICY = "public-builds,egress=metadata";
export type ModelVisibility = "tee" | "all";

/** Fixed upstream failure classes; provider bodies and messages are never kept. */
export type UpstreamClass = "rate-limited" | "upstream unavailable" | "evidence unavailable" | "request refused" | "connection failed";
export type UpstreamCause = Readonly<{ status?: number; class: UpstreamClass }>;

export class TeeError extends Error {
  readonly upstream?: UpstreamCause;
  constructor(readonly code: string, message = code, upstream?: UpstreamCause) {
    super(message);
    this.name = "TeeError";
    if (upstream) this.upstream = upstream;
  }
}

/** Without a status, the request never received a response. */
export function upstreamFailure(code: string, status?: number, phase: "evidence" | "request" = "request") {
  const upstream: UpstreamCause = status === undefined ? { class: "connection failed" } : {
    status, class: status === 429 ? "rate-limited" : status >= 500 ? "upstream unavailable" : phase === "evidence" ? "evidence unavailable" : "request refused",
  };
  return new TeeError(code, code, Object.freeze(upstream));
}

export function describeUpstream(cause: UpstreamCause) {
  return cause.status === undefined ? cause.class : `HTTP ${cause.status} ${cause.class}`;
}

export function resolvePolicy(value?: string): PolicyMode {
  parsePolicy(value);
  return value ?? DEFAULT_POLICY;
}

/** Position names disclose permitted trust. Reject contradictory refinements rather
 * than silently weakening them; recognize future build/review values only to
 * return an explicit unsupported-setting error, never as an approval alias. */
export function parsePolicy(value = DEFAULT_POLICY): SecurityPolicy {
  const [name, ...settings] = value.split(",");
  function invalid(message: string): never { throw new TeeError("TEE_POLICY_INVALID", `TEE_POLICY_INVALID: ${message}`); }
  if (name === "sdk") invalid("sdk was removed; use PI_TEE_POLICY=trust-provider-and-host. Add host=current to reject outdated instances (and the stale Tinfoil router).");
  if (name === "approved") invalid("approved was removed; use public-builds,review=pinned (not yet supported).");
  if (!POSITIONS.includes(name as Position)) invalid(`Unknown position '${name}'; use ${POSITIONS.join(", ")}.`);
  const position = name as Position;
  const publicCode = position.startsWith("public-builds");
  const trustsHost = position.endsWith("trust-host") || position === "trust-provider-and-host";
  const policy: { -readonly [K in keyof SecurityPolicy]: SecurityPolicy[K] } = {
    position, code: publicCode ? "public-release" : "provider-controlled",
    host: trustsHost ? "stale" : "current", gpu: trustsHost ? "unchecked" : "verified",
    egress: publicCode ? "none" : "any", verifier: "local", warnings: [],
    ...(publicCode ? { build: "publisher-workflow" as const, review: "none" as const } : {}),
  };
  const seen = new Set<string>();
  for (const setting of settings) {
    const [axis, choice, extra] = setting.split("=");
    if (!axis || !choice || extra !== undefined || !Object.hasOwn(POLICY_VALUES, axis)) invalid(`Invalid setting '${setting}'.`);
    if (seen.has(axis)) invalid(`Duplicate ${axis} setting.`);
    seen.add(axis);
    const values: readonly string[] = POLICY_VALUES[axis as keyof typeof POLICY_VALUES];
    if (!values.includes(choice!)) invalid(`Invalid ${axis}=${choice}; use ${values.join(" | ")}.`);
    Object.assign(policy, { [axis]: choice });
  }
  if ((policy.code === "public-release") !== publicCode) invalid(`${position} requires code ${publicCode ? "public-release" : "fixed-private or provider-controlled"}; use the matching position.`);
  if (policy.code !== "public-release") {
    if (policy.egress !== "any") invalid("code below public-release forces egress=any.");
    if (seen.has("build") || seen.has("review")) invalid("build and review refine public-release admission only.");
  }
  if (policy.host === "stale" && policy.gpu !== "unchecked") invalid("host=stale forces gpu=unchecked.");
  const excludesHost = policy.host === "current" && policy.gpu === "verified";
  if (excludesHost === trustsHost) invalid(`${position} requires ${trustsHost ? "host below current or gpu below verified" : "host=current,gpu=verified"}; use the matching position.`);
  if (policy.build === "reproduced" || policy.build === "reproduced-off-github" || policy.build === "signed") invalid(`build=${policy.build} is not yet supported; use publisher-workflow.`);
  if (policy.review === "window" || policy.review === "pinned") invalid(`review=${policy.review} is not yet supported; use none.`);
  if (policy.verifier === "nras" && policy.gpu === "unchecked") policy.warnings = ["verifier=nras has no effect with gpu=unchecked; GPU evidence is not appraised for admission."];
  return Object.freeze(policy);
}

export function resolveModelVisibility(value?: string): ModelVisibility {
  if (value === undefined || value === "tee") return "tee";
  if (value === "all") return "all";
  throw new TeeError("TEE_MODEL_VISIBILITY_INVALID");
}
