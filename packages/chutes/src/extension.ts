import { formatProviderReport, TeeError } from "pi-tee-core";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createChutesProvider } from "./index.js";

export default async function chutes(pi: ExtensionAPI) {
  const integration = createChutesProvider();
  if (process.env.PI_TEE_OFFLINE !== "1") await integration.initializeCatalog().catch(() => undefined);
  pi.registerProvider(integration.provider);
  const show = (ctx: ExtensionContext) => {
    const report = integration.getReport();
    ctx.ui.setStatus("chutes-policy", ctx.model?.provider === "chutes" ? `Chutes: ${report.policy} / ${report.lastRequest}` : undefined);
  };
  pi.on("session_start", async (_event, ctx) => show(ctx));
  pi.on("model_select", async (_event, ctx) => show(ctx));
  pi.on("message_end", async (_event, ctx) => show(ctx));
  pi.registerCommand("chutes", {
    description: "Chutes policy/report; /chutes policy <position>[,axis=value…]; /chutes models [refresh]",
    handler: async (args, ctx) => {
      try {
        if (args.startsWith("policy ")) {
          integration.setPolicy(args.slice(7));
          await ctx.modelRegistry.refresh({ providers: ["chutes"], allowNetwork: false });
        }
        else if (args === "models") {
          ctx.ui.notify(JSON.stringify(integration.getDiscoveredModels(), null, 2), "info");
          return;
        }
        else if (args === "models refresh") {
          const result = await ctx.modelRegistry.refresh({ providers: ["chutes"], force: true, allowNetwork: true });
          if (result.errors.has("chutes")) ctx.ui.notify("Chutes model refresh failed; cached catalog retained.", "warning");
        } else if (args && args !== "status") {
          ctx.ui.notify("Use /chutes status, /chutes policy <position>[,axis=value…], or /chutes models [refresh].", "warning");
          return;
        }
        const report = integration.getReport();
        ctx.ui.notify(formatProviderReport(report), "info");
        show(ctx);
      } catch (error) { ctx.ui.notify(error instanceof TeeError ? error.message : "Chutes command failed. Run /chutes status for the current policy.", "error"); }
    },
  });
}
