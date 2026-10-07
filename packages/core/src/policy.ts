export type PolicyMode = "approved" | "sdk";

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
