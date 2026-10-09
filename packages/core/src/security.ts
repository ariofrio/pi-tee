import { TeeError, POLICY_VALUES, type SecurityPolicy } from "./policy.js";

export interface RouteSecurity {
  route: string;
  provider: string;
  cpuVerified: boolean;
  code: 1 | 2 | 3;
  host: 1 | 2 | 3;
  gpu: 1 | 2 | 3;
  egress: 1 | 2 | 3;
  build?: 1 | 2 | 3 | 4;
  review?: 1 | 2 | 3;
  observed: readonly string[];
}
/** Adapter-owned request diagnostics; no security levels are implied. */
export class RouteFailure extends TeeError {
  readonly notes: readonly string[];
  constructor(readonly route: string, code: string, notes: readonly string[] = []) {
    super(code);
    this.notes = Object.freeze([...notes]);
  }
}

/** Authenticated candidate levels retained when no worker meets policy. */
export class RouteRejection extends RouteFailure {
  readonly security: RouteSecurity;
  constructor(security: RouteSecurity, notes: readonly string[] = []) {
    super(security.route, "TEE_POLICY_ROUTE_REJECTED", notes);
    this.security = Object.freeze(structuredClone(security));
  }
}

export interface RouteDecision {
  route: string;
  security?: RouteSecurity;
  accepted: boolean;
  picked: boolean;
  reason: string;
  notes?: readonly string[];
  trusts: readonly string[];
  gaps: readonly string[];
}
export const ROUTE_AXES = ["code", "host", "gpu", "egress"] as const;

/** Verified means client-checked hardware/manufacturer signatures or output of
 * A1-verified code. Data assembled by code below A1 is unverified. Catalog
 * metadata and provider-assembled coverage cannot establish actual levels. */
export function assessRoute(policy: SecurityPolicy, route: RouteSecurity): Omit<RouteDecision, "picked"> {
  const failures: string[] = [];
  if (!route.cpuVerified) failures.push("CPU evidence was not verified; route is out of scope");
  for (const axis of ROUTE_AXES) {
    const actual = route[axis];
    if (!Number.isInteger(actual) || actual < 1 || actual > 3 || actual > POLICY_VALUES[axis].indexOf(policy[axis] as never) + 1) failures.push(`${axis} level ${actual} exceeds ${axis}=${policy[axis]}`);
  }
  if (route.host === 3 && route.gpu < 3) failures.push("stale CPU evidence cannot establish G1 or G2");
  if (route.code > 1 && route.egress < 3) failures.push("private or unknown code cannot establish an egress limit");
  if (route.code === 1 && policy.code === "public-release") {
    for (const axis of ["build", "review"] as const) {
      const level = route[axis];
      if (level === undefined || !Number.isInteger(level) || level < 1 || level > (axis === "build" ? 4 : 3) || level > POLICY_VALUES[axis].indexOf(policy[axis] as never) + 1) failures.push(`${axis} does not meet ${policy[axis]}`);
    }
  }
  const gaps: string[] = [];
  const trusts: string[] = ["Intel, AMD and NVIDIA as manufacturers; your machine and Pi"];
  if (policy.verifier === "nras" && route.gpu < 3) {
    trusts.push("NVIDIA NRAS service keys, insiders and appraisal policy");
    gaps.push("NRAS learns which GPUs are attested and when; admission depends on its availability.");
  }
  if (route.code > 1) {
    trusts.push(`${route.provider}, which can read plaintext${route.code === 3 ? " and change serving code without the client noticing" : "; private code is pinned but its behavior is unknown"}`);
    gaps.push(route.code === 3 ? "A3: serving code is provider-controlled" : "A2: fixed private code cannot be inspected");
  }
  if (route.host > 1 || route.gpu > 1) {
    trusts.push("the host, which has known ways to reach plaintext");
    if (route.code === 1) gaps.push("Provider exclusion assumes the host is separate and does not collude with the provider; if it does, both are trusted.");
  }
  if (route.host === 2) gaps.push("H2: fresh CPU evidence is below pi-tee's floors, or those floors could not be established");
  if (route.host === 3) gaps.push("H3: CPU evidence is stale and not held to pi-tee's floors");
  if (route.gpu === 2) gaps.push("G2: GPU setup has known gaps");
  if (route.gpu === 3) gaps.push("G3: no complete evidence shows all GPUs serving the request");
  if (route.egress === 2) gaps.push("X2: authorization metadata may leave; admitted code does not store plaintext");
  if (route.egress === 3) gaps.push("X3: bodies may leave or be stored; no verified handling limit");
  if (route.code === 1) {
    gaps.push(route.build === 4 ? "B4: release is signed, workflow and runner are unchecked" : "B3: publisher workflow; independent reproduction is not established");
    if (route.review === 3) gaps.push("S3: no review window or pinned independent review");
    trusts.push("the admitted public release publishers; GitHub and Sigstore for build attribution");
  }
  gaps.push(...route.observed, "Physical attacks on the serving host are outside this model.");
  return { route: route.route, security: route, accepted: failures.length === 0, reason: failures.join("; ") || "meets every threshold", trusts, gaps };
}

/** Negative means left is stronger. B/S are admission refinements, not tie-break axes. */
export function compareRoutes(left: RouteSecurity, right: RouteSecurity): number {
  for (const axis of ROUTE_AXES) if (left[axis] !== right[axis]) return left[axis] - right[axis];
  return 0;
}

/** Every plaintext or key recipient contributes its weakest level. An empty
 * inventory cannot establish CPU verification or inherit a stronger component. */
export function weakestRoute(route: string, provider: string, components: readonly RouteSecurity[]): RouteSecurity {
  return {
    route, provider, cpuVerified: components.length > 0 && components.every(c => c.cpuVerified),
    code: Math.max(3 * Number(components.length === 0), ...components.map(c => c.code)) as RouteSecurity["code"],
    host: Math.max(3 * Number(components.length === 0), ...components.map(c => c.host)) as RouteSecurity["host"],
    gpu: Math.max(3 * Number(components.length === 0), ...components.map(c => c.gpu)) as RouteSecurity["gpu"],
    egress: Math.max(3 * Number(components.length === 0), ...components.map(c => c.egress)) as RouteSecurity["egress"],
    build: Math.max(4 * Number(components.length === 0), ...components.map(c => c.build ?? 4)) as RouteSecurity["build"],
    review: Math.max(3 * Number(components.length === 0), ...components.map(c => c.review ?? 3)) as RouteSecurity["review"],
    observed: [...new Set(components.flatMap(c => c.observed))],
  };
}
