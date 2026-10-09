import { formatProviderReport, TeeError } from "pi-tee-core";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createNearProvider } from "./index.js";

export default async function nearai(pi: ExtensionAPI) {
  const integration = createNearProvider();
  if (process.env.PI_TEE_OFFLINE !== "1") await integration.initializeCatalog().catch(() => undefined);
  pi.registerProvider(integration.provider);
  const show = (ctx: ExtensionContext) => {
    const report = integration.getReport();
    ctx.ui.setStatus("nearai-policy", ctx.model?.provider === "nearai" ? `NEAR AI: ${report.policy} / ${report.lastRequest}` : undefined);
  };
  pi.on("session_start", async (_event, ctx) => show(ctx));
  pi.on("model_select", async (_event, ctx) => show(ctx));
  pi.on("message_end", async (_event, ctx) => show(ctx));
  pi.registerCommand("nearai", {
    description: "NEAR AI policy/report; /nearai policy <position>[,axis=value…]; /nearai models tee|all|refresh",
    handler: async (args, ctx) => {
      try {
        if (args.startsWith("policy ")) {
          integration.setPolicy(args.slice(7));
          await ctx.modelRegistry.refresh({ providers: ["nearai"], allowNetwork: false });
        }
        else if (args === "models tee" || args === "models all") {
          integration.setModelVisibility(args.slice(7));
          await ctx.modelRegistry.refresh({ providers: ["nearai"], allowNetwork: false });
        }
        else if (args === "models") {
          ctx.ui.notify(JSON.stringify(integration.getDiscoveredModels(), null, 2), "info");
          return;
        }
        else if (args === "models refresh") {
          const result = await ctx.modelRegistry.refresh({ providers: ["nearai"], force: true, allowNetwork: true });
          if (result.errors.has("nearai")) ctx.ui.notify("NEAR AI model refresh failed; cached catalog retained.", "warning");
        } else if (args && args !== "status") {
          ctx.ui.notify("Use /nearai status, /nearai policy <position>[,axis=value…], or /nearai models tee|all|refresh.", "warning");
          return;
        }
        const report = integration.getReport();
        ctx.ui.notify(formatProviderReport(report), "info");
        show(ctx);
      } catch (error) { ctx.ui.notify(error instanceof TeeError ? error.message : "NEAR AI command failed. Run /nearai status for the current policy.", "error"); }
    },
  });
}
