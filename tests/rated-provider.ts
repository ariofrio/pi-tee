import { createTeeProvider, type ProviderDefinition } from "../packages/core/src/provider.js";
import { parsePolicy } from "../packages/core/src/policy.js";

/** Synthetic actual ratings at the external transport seam for guard tests. */
export function createRatedTestProvider(definition: ProviderDefinition) {
  if (definition.routes || definition.publicBuildProfile || definition.publicBuildProfiles || parsePolicy(definition.policy).code === "public-release") return createTeeProvider(definition);
  const security = { route: "synthetic-sdk", provider: definition.name, cpuVerified: true, code: 3 as const, host: 3 as const, gpu: 3 as const, egress: 3 as const, observed: [] };
  return createTeeProvider({ ...definition, routes: [{ id: security.route, potential: security,
    openSession: async context => ({ security, transport: await definition.openSdkTransport(context) }),
  }] });
}
