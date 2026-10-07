#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chmod, copyFile, stat, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { NVIDIA_ARCHIVE, GPU_DEPENDENCIES, GPU_DOCKERFILE, GPU_IMAGE_ARCHIVE_SHA256 } from "./setup-artifacts.js";
import { INTEL_CANDIDATE, NVAT_HASHES, PUBLIC_BUILD_VERIFIER_SHA256 } from "./intel-appraisal.js";

const execute = promisify(execFile);
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
function fail(code: string): never { throw new Error(code); }

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") {
    console.log("pi-tinfoil-setup --directory ABSOLUTE_PATH [--verify-cache-only]\nBuilds locked local verifiers for macOS ARM64; requires Go and local Docker/buildx. No credentials or inference.");
    return;
  }
  const index = args.indexOf("--directory");
  if (index !== 0 || !args[1] || args.some((arg, position) => position > 1 && arg !== "--verify-cache-only")) fail("TEE_SETUP_ARGUMENT_REJECTED");
  const directory = resolve(args[1]);
  if (directory !== args[1]) fail("TEE_SETUP_ARGUMENT_REJECTED");
  const verifyOnly = args.includes("--verify-cache-only");
  if (!verifyOnly && (process.platform !== "darwin" || process.arch !== "arm64")) fail("TEE_SETUP_RUNTIME_UNSUPPORTED");
  const downloads = resolve(directory, "downloads");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
  await mkdir(downloads, { recursive: true, mode: 0o700 });
  const signal = AbortSignal.timeout(600000);
  async function artifact(item: { name: string; url: string; size: number; sha256: string }) {
    const path = resolve(downloads, item.name);
    let bytes: Buffer | undefined;
    try { if ((await stat(path)).size !== item.size) fail("TEE_SETUP_ARTIFACT_REJECTED"); bytes = await readFile(path); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") fail("TEE_SETUP_ARTIFACT_REJECTED"); }
    if (!bytes && !verifyOnly) {
      const response = await fetch(item.url, { signal, redirect: "error" });
      if (!response.ok || !response.body) fail("TEE_SETUP_DOWNLOAD_REJECTED");
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = []; let count = 0;
      try {
        for (;;) {
          const next = await reader.read(); if (next.done) break;
          count += next.value.length;
          if (count > item.size) { await reader.cancel(); fail("TEE_SETUP_ARTIFACT_REJECTED"); }
          chunks.push(next.value);
        }
      } finally { reader.releaseLock(); }
      bytes = Buffer.concat(chunks);
    }
    if (!bytes || bytes.length !== item.size || hash(bytes) !== item.sha256) fail("TEE_SETUP_ARTIFACT_REJECTED");
    if (!verifyOnly) await writeFile(path, bytes, { mode: 0o600, signal });
    return path;
  }
  const packages: string[] = [];
  for (const item of GPU_DEPENDENCIES) packages.push(await artifact(item));
  const archive = await artifact(NVIDIA_ARCHIVE);
  if (verifyOnly) { console.log("PASS: pinned setup artifacts."); return; }
  const environment = { PATH: process.env.PATH, HOME: process.env.HOME, GOTOOLCHAIN: "go1.26.6", GOMAXPROCS: "2" };
  const run = (file: string, args: string[], cwd?: string) => execute(file, args, { env: environment, cwd, signal, timeout: 300000, maxBuffer: 1024 * 1024 });
  const helper = resolve(directory, "tinfoil-public-build-verifier");
  const source = resolve(dirname(fileURLToPath(import.meta.url)), "../verifier-source");
  console.log("Building the locked CPU verifier.");
  await run("go", ["build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-p=1", "-o", helper, "."], source);
  if (hash(await readFile(helper)) !== PUBLIC_BUILD_VERIFIER_SHA256) fail("TEE_SETUP_VERIFIER_REJECTED");
  const scratch = await mkdtemp(resolve(directory, "setup-"));
  try {
    await run("tar", ["-xf", archive, "-C", scratch]);
    const name = "libnvat-linux-sbsa-1.2.2.1780962352-archive";
    const extracted = resolve(scratch, name);
    for (const [path, digest] of Object.entries(NVAT_HASHES)) if (hash(await readFile(resolve(extracted, path))) !== digest) fail("TEE_SETUP_VERIFIER_REJECTED");
    const context = resolve(scratch, "image");
    await mkdir(context, { mode: 0o700 });
    await writeFile(resolve(context, "Dockerfile"), GPU_DOCKERFILE, { mode: 0o600 });
    for (const path of packages) {
      const copied = resolve(context, path.split("/").at(-1)!);
      await copyFile(path, copied); await chmod(copied, 0o644);
    }
    console.log("Building the pinned GPU execution image without RUN network access.");
    const imageTar = resolve(scratch, "image.tar");
    await run("docker", ["buildx", "build", "--platform", "linux/arm64", "--network=none", "--no-cache", "--build-arg", "SOURCE_DATE_EPOCH=0", "--provenance=false", "--sbom=false", "--output", `type=oci,dest=${imageTar},rewrite-timestamp=true`, context]);
    if (hash(await readFile(imageTar)) !== GPU_IMAGE_ARCHIVE_SHA256) fail("TEE_SETUP_VERIFIER_REJECTED");
    await run("docker", ["load", "--input", imageTar]);
    const image = await run("docker", ["image", "inspect", INTEL_CANDIDATE.gpuImage, "--format", "{{.Id}}"]);
    if (image.stdout.trim() !== INTEL_CANDIDATE.gpuImage) fail("TEE_SETUP_VERIFIER_REJECTED");
    const destination = resolve(directory, name);
    await mkdir(destination, { recursive: true, mode: 0o700 });
    // Copy the authenticated archive into its final location only after checks.
    await run("tar", ["-xf", archive, "-C", directory]);
    console.log(`PASS: local verifier setup.\nPI_TINFOIL_PUBLIC_BUILD_VERIFIER=${helper}\nPI_TINFOIL_NVAT_DIR=${destination}`);
  } finally { await rm(scratch, { recursive: true, force: true }); }
}

void main().catch(error => {
  const code = error instanceof Error && /^TEE_SETUP_[A-Z_]+$/.test(error.message) ? error.message : "TEE_SETUP_FAILED";
  console.error(code); process.exitCode = 1;
});
