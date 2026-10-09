import { formatProviderReport, registerSecurityStatus, TeeError } from "pi-tee-core";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createTinfoilProvider } from "./index.js";

export default async function tinfoil(pi: ExtensionAPI) {
  const integration = createTinfoilProvider();
  if (process.env.PI_TEE_OFFLINE !== "1") await integration.initializeCatalog().catch(() => undefined);
  pi.registerProvider(integration.provider);
  registerSecurityStatus(pi.registerCommand.bind(pi), integration.provider.id, () => integration.getReport());
  const show = (ctx: ExtensionContext) => {
    const report = integration.getReport();
    ctx.ui.setStatus("tinfoil-policy", ctx.model?.provider === "tinfoil" ? `Tinfoil: ${report.policy} / ${report.lastRequest}` : undefined);
  };
  pi.on("session_start", async (_event, ctx) => show(ctx));
  pi.on("model_select", async (_event, ctx) => show(ctx));
  pi.on("message_end", async (_event, ctx) => show(ctx));
  pi.registerCommand("tinfoil", {
    description: "Tinfoil policy/report; /tinfoil policy <position>[,axis=value…]; /tinfoil models refresh",
    handler: async (args, ctx) => {
      try {
        if (args.startsWith("policy ")) {
          integration.setPolicy(args.slice(7));
          await ctx.modelRegistry.refresh({ providers: ["tinfoil"], allowNetwork: false });
        }
        else if (args === "models") {
          ctx.ui.notify(JSON.stringify(integration.getDiscoveredModels(), null, 2), "info");
          return;
        }
        else if (args === "models refresh") {
          const result = await ctx.modelRegistry.refresh({ providers: ["tinfoil"], force: true, allowNetwork: true });
          if (result.errors.has("tinfoil")) ctx.ui.notify("Tinfoil model refresh failed; cached catalog retained.", "warning");
        } else if (args && args !== "status") {
          ctx.ui.notify("Use /tinfoil status, /tinfoil policy <position>[,axis=value…], or /tinfoil models refresh.", "warning");
          return;
        }
        const report = integration.getReport();
        ctx.ui.notify(formatProviderReport(report), "info");
        show(ctx);
      } catch (error) { ctx.ui.notify(error instanceof TeeError ? error.message : "Tinfoil command failed. Run /tinfoil status for the current policy.", "error"); }
    },
  });
}
