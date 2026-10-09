import { formatProviderReport, TeeError } from "pi-tee-core";
import type {
  ExtensionAPI,
  ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { createPrivatemodeProvider } from "./index.js";

export default async function privatemode(pi: ExtensionAPI) {
  const integration = createPrivatemodeProvider();
  if (process.env.PI_TEE_OFFLINE !== "1")
    await integration.initializeCatalog().catch(() => undefined);
  pi.registerProvider(integration.provider);
  const show = (ctx: ExtensionContext) => {
    const report = integration.getReport();
    ctx.ui.setStatus(
      "privatemode-policy",
      ctx.model?.provider === "privatemode"
        ? `Privatemode: ${report.policy} / ${report.lastRequest}`
        : undefined,
    );
  };
  pi.on("session_start", async (_event, ctx) => show(ctx));
  pi.on("model_select", async (_event, ctx) => show(ctx));
  pi.on("message_end", async (_event, ctx) => show(ctx));
  pi.registerCommand("privatemode", {
    description:
      "Privatemode policy/report; /privatemode policy <position>[,axis=value…]; /privatemode models [refresh]",
    handler: async (args, ctx) => {
      try {
        if (args.startsWith("policy ")) {
          integration.setPolicy(args.slice(7));
          await ctx.modelRegistry.refresh({
            providers: ["privatemode"],
            allowNetwork: false,
          });
        } else if (args === "models") {
          ctx.ui.notify(
            JSON.stringify(integration.getDiscoveredModels(), null, 2),
            "info",
          );
          return;
        } else if (args === "models refresh") {
          const result = await ctx.modelRegistry.refresh({
            providers: ["privatemode"],
            force: true,
            allowNetwork: true,
          });
          if (result.errors.has("privatemode"))
            ctx.ui.notify(
              "Privatemode model refresh failed; cached catalog retained.",
              "warning",
            );
        } else if (args && args !== "status") {
          ctx.ui.notify(
            "Use /privatemode status, /privatemode policy <position>[,axis=value…], or /privatemode models [refresh].",
            "warning",
          );
          return;
        }
        const report = integration.getReport();
        ctx.ui.notify(formatProviderReport(report), "info");
        show(ctx);
      } catch (error) {
        ctx.ui.notify(
          error instanceof TeeError
            ? error.message
            : "Privatemode command failed. Run /privatemode status for the current policy.",
          "error",
        );
      }
    },
  });
}
