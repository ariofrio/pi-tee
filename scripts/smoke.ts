import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { resolve, join } from "node:path";
import { ExtensionRunner, ModelRegistry, SessionManager, createAgentSessionServices } from "@earendil-works/pi-coding-agent";

await mkdir(".scratch/work", { recursive: true });
const scratch = await mkdtemp(resolve(".scratch/work/pi-loader-"));
const oldOffline = process.env.PI_TEE_OFFLINE;
process.env.PI_TEE_OFFLINE = "1";
try {
  const services = await createAgentSessionServices({
    cwd: join(scratch, "project"), agentDir: join(scratch, "agent"),
    resourceLoaderOptions: { additionalExtensionPaths: [
      resolve("packages/nearai/dist/extension.js"), resolve("packages/tinfoil/dist/extension.js"), resolve("packages/chutes/dist/extension.js"),
    ] },
  });
  const errors = services.diagnostics.filter((entry) => entry.type === "error");
  assert.equal(errors.length, 0, errors.map((entry) => entry.message).join("\n"));
  assert.deepEqual(services.resourceLoader.getExtensions().errors, []);
  const loaded = services.resourceLoader.getExtensions();
  const runner = new ExtensionRunner(loaded.extensions, loaded.runtime, join(scratch, "project"), SessionManager.inMemory(join(scratch, "project")), new ModelRegistry(services.modelRuntime));
  assert.deepEqual(runner.getRegisteredCommands().map(command => command.invocationName).sort(), ["chutes", "nearai", "tinfoil"]);
  assert.deepEqual(runner.getCommandDiagnostics(), []);
  for (const id of ["chutes", "nearai", "tinfoil"]) {
    const provider = services.modelRuntime.getProvider(id);
    assert.ok(provider, `${id} provider registered`);
    assert.equal(typeof provider.auth.apiKey?.login, "function", `${id} native API-key login available`);
    assert.equal(typeof provider.refreshModels, "function", `${id} native catalog refresh available`);
    const credential = await services.modelRuntime.login(id, "api_key", {
      prompt: async (prompt) => { assert.equal(prompt.type, "secret"); return "synthetic-smoke-key"; },
      notify: () => undefined,
    });
    assert.equal(credential.type, "api_key");
  }
  console.log("PASS: all compiled extension entries load through Pi's resource loader, with native login and refresh.");
} finally {
  if (oldOffline === undefined) delete process.env.PI_TEE_OFFLINE;
  else process.env.PI_TEE_OFFLINE = oldOffline;
  await rm(scratch, { recursive: true, force: true });
}
