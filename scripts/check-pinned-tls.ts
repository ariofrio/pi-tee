import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { resolve } from "node:path";

// Maintainer checks only. End-user packaging will supply reviewed platform artifacts.
if (process.env.PI_TEE_TEST_EXPECTED_ARCH) assert.equal(process.arch, process.env.PI_TEE_TEST_EXPECTED_ARCH);
await mkdir(".scratch/work", { recursive: true });
const scratch = await mkdtemp(resolve(".scratch/work/pinned-tls-check-"));
const tool = resolve("tools/pinned-tls");
const executable = resolve(scratch, process.platform === "win32" ? "pinned-tls.exe" : "pinned-tls");
const repeated = executable + ".repeat";
const lateReady = resolve(scratch, process.platform === "win32" ? "late-ready.exe" : "late-ready");
function run(file: string, args: string[], cwd: string, env: NodeJS.ProcessEnv) {
  const result = spawnSync(file, args, { cwd, env, stdio: "inherit", timeout: 180000 });
  assert.equal(result.status, 0, `${file} did not complete successfully`);
}
try {
  const env = { ...process.env, GOTOOLCHAIN: "go1.26.6" };
  run("go", ["test", "./..."], tool, env);
  run("go", ["test", "-run=^TestGenerateFixture$", "-count=1"], tool, { ...env, PI_TEE_TLS_TEST_FIXTURE_DIR: scratch });
  for (const output of [executable, repeated]) run("go", ["build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", output, "."], tool, { ...env, CGO_ENABLED: "0" });
  const digest = createHash("sha256").update(await readFile(executable)).digest("hex");
  assert.equal(createHash("sha256").update(await readFile(repeated)).digest("hex"), digest, "Repeated transport builds must match");
  run("go", ["build", "-trimpath", "-buildvcs=false", "-o", lateReady, "./testdata/late-ready"], tool, { ...env, CGO_ENABLED: "0" });
  console.log(`PASS: repeated native transport build (${process.platform}/${process.arch}) SHA-256 ${digest}.`);
  const testEnv = { ...process.env, PI_TEE_PINNED_TLS_TEST_HELPER: executable, PI_TEE_PINNED_TLS_TEST_STUB: lateReady, PI_TEE_TLS_TEST_FIXTURE_DIR: scratch };
  if (process.argv.includes("--bun")) {
    run("bun", ["test", "tests/pinned-tls-helper.test.ts"], process.cwd(), { ...testEnv, PI_TEE_PINNED_TLS_TEST_NODE: process.execPath });
  } else run(process.execPath, ["--import", "tsx", "--test", "tests/pinned-tls-helper.test.ts", "tests/pinned-tls.test.ts"], process.cwd(), testEnv);
} finally { await rm(scratch, { recursive: true, force: true }); }
