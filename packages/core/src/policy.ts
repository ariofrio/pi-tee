export type PolicyMode = "approved" | "sdk";
export type ModelVisibility = "tee" | "all";

export class TeeError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "TeeError";
  }
}

export function resolvePolicy(value?: string): PolicyMode {
  if (value === undefined || value === "approved") return "approved";
  if (value === "sdk") return "sdk";
  throw new TeeError("TEE_POLICY_INVALID");
}

export function resolveModelVisibility(value?: string): ModelVisibility {
  if (value === undefined || value === "tee") return "tee";
  if (value === "all") return "all";
  throw new TeeError("TEE_MODEL_VISIBILITY_INVALID");
}
