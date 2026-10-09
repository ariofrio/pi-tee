import { parsePolicy } from "./policy.js";
import type { ProviderReport } from "./provider.js";

/** Human-readable, request-specific evidence and choices; never uses potential levels as observations. */
export function formatProviderReport(report: ProviderReport): string {
  const policy = report.settings ?? parsePolicy(report.policy);
  const providerTrust = policy.code !== "public-release";
  const hostTrust = policy.host !== "current" || policy.gpu !== "verified";
  const lines = [
    `${report.provider}: ${report.lastRequest}`,
    `Position: ${policy.position}`,
    `Position permits trust in: ${[...(providerTrust ? ["the provider"] : []), ...(hostTrust ? ["the host"] : [])].join(" and ") || "neither the provider nor the host"}.`,
    `Thresholds: code=${policy.code}, host=${policy.host}, gpu=${policy.gpu}, egress=${policy.egress}${policy.build ? `, build=${policy.build}, review=${policy.review}` : ""}; verifier=${policy.verifier}.`,
    ...policy.warnings.map(warning => `Warning: ${warning}`),
  ];
  if (!report.routeDecisions?.length) lines.push("No request has established route levels yet.");
  for (const decision of report.routeDecisions ?? []) {
    const levels = decision.security;
    lines.push("", `${decision.route}${levels ? `: A${levels.code} H${levels.host} G${levels.gpu} X${levels.egress}${levels.build ? ` B${levels.build}` : ""}${levels.review ? ` S${levels.review}` : ""}` : ": levels not established"}`,
      `Choice: ${decision.reason}`, ...decision.trusts.map(trust => `Trusts: ${trust}`), ...decision.gaps.map(gap => `Gap / observation: ${gap}`));
  }
  if (report.reason) lines.push(`Request result: ${report.reason}`);
  lines.push("", "Scope: prompt, tool arguments and completion dispatches through this provider; whole-session protection is not established.",
    ...report.assumptions.map(assumption => `Assumption / limitation: ${assumption}`));
  return lines.join("\n");
}

const statusReports = new Map<string, () => ProviderReport>();
export function registerSecurityStatus(
  register: (name: string, command: { description: string; handler: (args: string, ctx: { model?: { provider: string }; ui: { notify(message: string, type: "info"): void } }) => Promise<void> }) => void,
  provider: string, getReport: () => ProviderReport,
): void {
  statusReports.set(provider, getReport);
  register("status", { description: "Confidential inference position, actual route levels, trusts, gaps and selection reasons", handler: async (_args, ctx) => {
    const current = ctx.model && statusReports.get(ctx.model.provider);
    const reports = current ? [current()] : [...statusReports.values()].map(get => get());
    ctx.ui.notify(reports.map(formatProviderReport).join("\n\n"), "info");
  } });
}
