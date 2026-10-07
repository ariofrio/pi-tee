import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);
const root = resolve(".");
// A sibling scratch directory prevents Node from falling back to this workspace's node_modules.
await mkdir("../work", { recursive: true });
const scratch = await mkdtemp(resolve("../work/pi-tee-package-smoke-"));
const packed = new Map<string, string>();
try {
  for (const name of ["core", "nearai", "tinfoil"]) {
    const { stdout } = await execute("npm", ["pack", `./packages/${name}`, "--ignore-scripts", "--json", "--pack-destination", scratch], { cwd: root });
    const [result] = JSON.parse(stdout) as { filename: string; files: { path: string }[] }[];
    assert.ok(result);
    const files = result.files.map((file) => file.path);
    for (const file of ["LICENSE", "README.md", "dist/index.js", "dist/index.d.ts", ...(name === "core" ? [] : ["dist/extension.js"])]) assert.ok(files.includes(file), `${name} includes ${file}`);
    if (name === "tinfoil") for (const file of ["dist/setup.js", "verifier-source/main.go", "verifier-source/go.mod", "verifier-source/go.sum", "verifier-source/trusted_root.json"]) assert.ok(files.includes(file), `tinfoil includes ${file}`);
    packed.set(name, join(scratch, result.filename));
  }
  for (const name of ["nearai", "tinfoil"]) {
    const directory = join(scratch, name);
    await mkdir(directory);
    await writeFile(join(directory, "package.json"), JSON.stringify({ name: `isolated-${name}-smoke`, private: true, type: "module" }));
    await execute("npm", ["install", "--prefer-offline", "--ignore-scripts", "--no-audit", "--no-fund", packed.get("core")!, packed.get(name)!], { cwd: directory, maxBuffer: 2 * 1024 * 1024 });
    if (name === "tinfoil") {
      const help = await execute(process.execPath, ["node_modules/pi-tinfoil/dist/setup.js", "--help"], { cwd: directory });
      assert.ok(help.stdout.includes("macOS ARM64"));
      if (process.env.PI_TEE_PACKAGE_SETUP_DIR) {
        const setup = await execute(process.execPath, ["node_modules/.bin/pi-tinfoil-setup", "--directory", resolve(process.env.PI_TEE_PACKAGE_SETUP_DIR)], {
          cwd: directory, env: { PATH: process.env.PATH, HOME: process.env.HOME }, timeout: 600000, maxBuffer: 1048576,
        });
        assert.ok(setup.stdout.includes("PASS: local verifier setup."));
        console.log("PASS: isolated tinfoil tarball reproduces the pinned local verifiers.");
      }
    }
    const otherSdk = name === "nearai" ? "tinfoil" : "@nearai/inference-sdk";
    await assert.rejects(access(join(directory, "node_modules", otherSdk)), { code: "ENOENT" });
    const code = `
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAgentSessionServices } from '@earendil-works/pi-coding-agent';
assert.throws(() => import.meta.resolve('${otherSdk}'), { code: 'ERR_MODULE_NOT_FOUND' });
assert.ok(fileURLToPath(import.meta.resolve('@earendil-works/pi-coding-agent')).startsWith(resolve('node_modules') + '/'));
assert.ok(fileURLToPath(import.meta.resolve('pi-tee-core')).startsWith(resolve('node_modules') + '/'));
const services = await createAgentSessionServices({
  cwd: resolve('project'), agentDir: resolve('agent'),
  resourceLoaderOptions: { additionalExtensionPaths: [resolve('node_modules/pi-${name}/dist/extension.js')] },
});
assert.deepEqual(services.resourceLoader.getExtensions().errors, []);
assert.equal(services.diagnostics.filter(entry => entry.type === 'error').length, 0);
const provider = services.modelRuntime.getProvider('${name}');
assert.ok(provider);
assert.deepEqual(provider.getModels(), []);
const credential = await services.modelRuntime.login('${name}', 'api_key', {
  prompt: async prompt => { assert.equal(prompt.type, 'secret'); return 'synthetic-smoke-key'; }, notify: () => undefined,
});
assert.equal(credential.type, 'api_key');
console.log('PASS: isolated ${name} tarball loads and logs in; offline catalog remains empty.');
`;
    await writeFile(join(directory, "smoke.mjs"), code);
    const { stdout } = await execute(process.execPath, ["smoke.mjs"], {
      cwd: directory, env: { ...process.env, PI_TEE_OFFLINE: "1", PI_NEARAI_POLICY: "public-builds", PI_TINFOIL_POLICY: "public-builds" },
    });
    process.stdout.write(stdout);
  }
} finally {
  await rm(scratch, { recursive: true, force: true });
}
