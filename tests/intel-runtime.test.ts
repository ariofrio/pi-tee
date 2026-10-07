import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { qualifyIntelCandidate } from "../packages/tinfoil/src/intel-appraisal.js";

for (const host of ["ssh://untrusted-verifier.invalid", "tcp://untrusted-verifier.invalid:2376", "unix:///unapproved/docker.sock"]) test(`Intel appraisal rejects an unapproved Docker endpoint (${host.split(":")[0]}) before collecting evidence`, async () => {
  const directory = await mkdtemp(resolve(".scratch/work/docker-location-"));
  const previousPath = process.env.PATH;
  let fetched = false;
  try {
    await writeFile(resolve(directory, "docker"), `#!${process.execPath}\nconsole.log(${JSON.stringify(JSON.stringify([{Name:"remote",Endpoints:{docker:{Host:host}}}]))});\n`, { mode: 0o700 });
    process.env.PATH = directory;
    await assert.rejects(qualifyIntelCandidate({
      cpuVerifier: resolve(directory, "absent-helper"), nvatDir: directory,
      mode: "public-builds", signal: AbortSignal.timeout(10000),
      evidenceFetch: (async () => { fetched = true; throw new Error("Unexpected evidence download"); }) as typeof fetch,
    }), /TEE_GPU_VERIFIER_LOCATION_REJECTED/);
    assert.equal(fetched, false);
  } finally {
    process.env.PATH = previousPath;
    await rm(directory, { recursive: true, force: true });
  }
});
