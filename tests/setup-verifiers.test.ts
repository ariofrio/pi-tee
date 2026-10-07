import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";

test("the verifier setup CLI rejects substituted cached dependencies without executing a builder", async () => {
  const directory = await mkdtemp(resolve(".scratch/work/setup-negative-"));
  try {
    await mkdir(resolve(directory, "downloads"));
    await writeFile(resolve(directory, "downloads", "ca-certificates_20260601~24.04.1_all.deb"), "substituted dependency");
    let result: { stdout: string; stderr: string; code?: number };
    try {
      result = await promisify(execFile)(process.execPath, ["--no-deprecation", "--import", "tsx", "packages/tinfoil/src/setup.ts", "--directory", directory, "--verify-cache-only"], {
        env: { PATH: "/nonexistent-builder-path" }, timeout: 15000, maxBuffer: 4096,
      });
    } catch (error) { result = error as typeof result; }
    assert.equal(result.code, 1);
    assert.equal(result.stderr.trim(), "TEE_SETUP_ARTIFACT_REJECTED");
    assert.equal(result.stdout, "");
  } finally { await rm(directory, { recursive: true, force: true }); }
});
