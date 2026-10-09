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
  for (const name of ["core", "nearai", "tinfoil", "chutes"]) {
    const { stdout } = await execute("npm", ["pack", `./packages/${name}`, "--ignore-scripts", "--json", "--pack-destination", scratch], { cwd: root });
    const [result] = JSON.parse(stdout) as { filename: string; files: { path: string }[] }[];
    assert.ok(result);
    const files = result.files.map((file) => file.path);
    for (const file of ["LICENSE", "README.md", "dist/index.js", "dist/index.d.ts", ...(name === "core" ? [] : ["dist/extension.js"])]) assert.ok(files.includes(file), `${name} includes ${file}`);
    if (name === "core") for (const file of ["wasm/nvattest.wasm.gz", "wasm/nvattest.mjs", "wasm/THIRD_PARTY_LICENSES.txt", "dist/nvattest-worker.js", "dist/nvattest-bridge.js"]) assert.ok(files.includes(file), `core includes ${file}`);
    if (name === "tinfoil") for (const file of ["wasm/tinfoil-public-build.wasm.gz", "wasm/THIRD_PARTY_LICENSES.txt"]) assert.ok(files.includes(file), `tinfoil includes ${file}`);
    packed.set(name, join(scratch, result.filename));
  }
  for (const name of ["nearai", "tinfoil", "chutes"]) {
    const directory = join(scratch, name);
    await mkdir(directory);
    await writeFile(join(directory, "package.json"), JSON.stringify({ name: `isolated-${name}-smoke`, private: true, type: "module" }));
    await execute("npm", ["install", "--prefer-offline", "--ignore-scripts", "--no-audit", "--no-fund", packed.get("core")!, packed.get(name)!], { cwd: directory, maxBuffer: 2 * 1024 * 1024 });
    const otherSdk = name === "nearai" ? "tinfoil" : "@nearai/inference-sdk";
    await assert.rejects(access(join(directory, "node_modules", otherSdk)), { code: "ENOENT" });
    const code = `
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAgentSessionServices } from '@earendil-works/pi-coding-agent';
// A nested worktree can resolve an unrelated SDK in an ancestor checkout.
// The tarball's installed dependency tree must still exclude it.
try {
  assert.ok(!fileURLToPath(import.meta.resolve('${otherSdk}')).startsWith(resolve('node_modules') + '/'));
} catch (error) {
  if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error;
}
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
      cwd: directory, env: { ...process.env, PI_TEE_OFFLINE: "1", PI_TEE_POLICY: "public-builds,egress=metadata" },
    });
    process.stdout.write(stdout);
  }
} finally {
  await rm(scratch, { recursive: true, force: true });
}
