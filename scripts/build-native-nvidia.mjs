import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

// Maintainer candidate builder only. No production artifact or route is selected.
const recipe = resolve("tools/nvidia-native");
const lock = JSON.parse(await readFile(resolve(recipe, "source-lock.json"), "utf8"));
const targets = {
  "darwin-arm64": ["arm64-osx", "aarch64-apple-darwin"],
  "darwin-x64": ["x64-osx", "x86_64-apple-darwin"],
  "linux-arm64": ["arm64-linux", "aarch64-unknown-linux-gnu"],
  "linux-x64": ["x64-linux", "x86_64-unknown-linux-gnu"],
  "win32-arm64": ["arm64-windows-static", "aarch64-pc-windows-msvc"],
  "win32-x64": ["x64-windows-static", "x86_64-pc-windows-msvc"],
};
const platform = `${process.platform}-${process.arch}`;
assert.ok(targets[platform], "This candidate builder covers desktop targets only.");
if (process.env.PI_TEE_TEST_EXPECTED_ARCH) assert.equal(process.arch, process.env.PI_TEE_TEST_EXPECTED_ARCH);
const [triplet, rustTarget] = targets[platform];
const root = resolve(process.env.PI_TEE_NATIVE_BUILD_DIR ?? ".scratch/work/nvidia-native");
await mkdir(root, { recursive: true });
const inheritedNames = [
  "PATH", "Path", "HOME", "USERPROFILE", "TEMP", "TMP", "TMPDIR", "SystemRoot", "SYSTEMROOT", "windir", "ComSpec", "COMSPEC",
  "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "LOCALAPPDATA", "APPDATA", "HOMEDRIVE", "HOMEPATH", "RUSTUP_HOME",
  "VSINSTALLDIR", "VCINSTALLDIR", "VCToolsInstallDir", "WindowsSdkDir", "WindowsSDKVersion", "WindowsSdkBinPath", "WindowsSdkVerBinPath",
  "UniversalCRTSdkDir", "UCRTVersion", "LIB", "LIBPATH", "INCLUDE", "DevEnvDir", "FrameworkDir", "FrameworkVersion",
  "VSCMD_ARG_TGT_ARCH", "VSCMD_ARG_HOST_ARCH",
];
const buildEnv = {
  ...Object.fromEntries(inheritedNames.filter(name => process.env[name] !== undefined).map(name => [name, process.env[name]])),
  TZ: "UTC", LANG: "C", LC_ALL: "C", RUSTUP_TOOLCHAIN: lock.rust,
  CARGO_HOME: resolve(root, "cargo-home"), VCPKG_BINARY_SOURCES: "clear", VCPKG_DISABLE_METRICS: "1",
};
function run(executable, args, cwd = root, env = buildEnv, capture = false) {
  const result = spawnSync(executable, args, { cwd, env, encoding: "utf8", stdio: capture ? "pipe" : "inherit", timeout: 1800000 });
  if (capture && result.status !== 0) process.stderr.write(result.stderr ?? "");
  assert.equal(result.status, 0, `${executable} failed (${result.error?.code ?? result.status})`);
  return result.stdout?.trim() ?? "";
}
async function source(name) {
  const path = resolve(root, name);
  if (!(await stat(path).catch(() => null))) run("git", ["clone", "--no-checkout", "-c", "core.autocrlf=false", lock[name].repository, path]);
  run("git", ["config", "core.autocrlf", "false"], path);
  run("git", ["checkout", "--detach", lock[name].commit], path);
  assert.equal(run("git", ["rev-parse", "HEAD"], path, buildEnv, true), lock[name].commit);
  assert.equal(run("git", ["diff", "--name-only", "HEAD"], path, buildEnv, true), "", `${name} source must be clean`);
  return path;
}
const sdk = await source("sdk"), regorus = await source("regorus"), vcpkg = await source("vcpkg");
// Hash-locked verification patches are applied to copies outside the pinned checkout.
const patched = resolve(root, "patched-source");
await rm(patched, { recursive: true, force: true });
for (const patch of lock.patches) {
  const patchPath = resolve(recipe, patch.file);
  assert.equal(createHash("sha256").update(await readFile(patchPath)).digest("hex"), patch.sha256);
  const original = await readFile(resolve(sdk, patch.source));
  assert.equal(createHash("sha256").update(original).digest("hex"), patch.sourceSha256);
  await mkdir(dirname(resolve(patched, patch.source)), { recursive: true });
  await writeFile(resolve(patched, patch.source), original);
  run("git", ["apply", "--unidiff-zero", patchPath], patched, { ...buildEnv, GIT_CEILING_DIRECTORIES: root });
  assert.equal(createHash("sha256").update(await readFile(resolve(patched, patch.source))).digest("hex"), patch.resultSha256);
}
const cargoLock = await readFile(resolve(recipe, "regorus.Cargo.lock"));
assert.equal(createHash("sha256").update(cargoLock).digest("hex"), lock.regorusCargoLockSha256);
await copyFile(resolve(recipe, "regorus.Cargo.lock"), resolve(regorus, "bindings/ffi/Cargo.lock"));
const cargo = process.env.PI_TEE_BUILD_CARGO ?? "cargo";
assert.match(run(cargo, ["--version"], root, buildEnv, true), new RegExp(`^cargo ${lock.rust.replaceAll(".", "\\.")} `));
const rustEnv = { ...buildEnv, CARGO_TARGET_DIR: resolve(root, "rust-build"),
  RUSTFLAGS: `--remap-path-prefix=${root}=/pi-tee-nvidia-build${process.platform === "win32" ? " -C target-feature=+crt-static" : ""}` };
run(cargo, ["build", "--release", "--locked", "--manifest-path", "bindings/ffi/Cargo.toml", "--features", "regorus/semver", "--target", rustTarget], regorus, rustEnv);
const regorusLibrary = resolve(root, "rust-build", rustTarget, "release", process.platform === "win32" ? "regorus_ffi.lib" : "libregorus_ffi.a");
assert.ok((await stat(regorusLibrary)).isFile());
const vcpkgBinary = resolve(vcpkg, process.platform === "win32" ? "vcpkg.exe" : "vcpkg");
if (!(await stat(vcpkgBinary).catch(() => null))) {
  if (process.platform === "win32") run("cmd", ["/d", "/c", "bootstrap-vcpkg.bat", "-disableMetrics"], vcpkg);
  else run("sh", ["bootstrap-vcpkg.sh", "-disableMetrics"], vcpkg);
}
const build = resolve(root, "build");
run("cmake", ["-S", recipe, "-B", build, "-DCMAKE_BUILD_TYPE=Release",
  ...(process.platform === "win32" ? ["-A", process.arch === "arm64" ? "ARM64" : "x64"] : []),
  `-DCMAKE_TOOLCHAIN_FILE=${resolve(vcpkg, "scripts/buildsystems/vcpkg.cmake")}`,
  `-DVCPKG_TARGET_TRIPLET=${triplet}`, `-DNVIDIA_SOURCE=${sdk}`, `-DPATCHED_SOURCE=${patched}`, `-DREGORUS_SOURCE=${regorus}`, `-DREGORUS_LIBRARY=${regorusLibrary}`], root, buildEnv);
run("cmake", ["--build", build, "--config", "Release", "--parallel", "2"]);
const output = resolve(root, "artifact");
run("cmake", ["--install", build, "--config", "Release", "--prefix", output]);
const executable = resolve(output, "bin", process.platform === "win32" ? "nvattest.exe" : "nvattest");
await mkdir(resolve(output, "share"), { recursive: true });
await mkdir(resolve(output, "modules"), { recursive: true });
const opensslConfig = await readFile(resolve(recipe, "openssl.cnf"));
assert.equal(createHash("sha256").update(opensslConfig).digest("hex"), lock.opensslConfigSha256);
await writeFile(resolve(output, "share/openssl.cnf"), opensslConfig);
run(executable, ["version"]);
await writeFile(resolve(output, "candidate-inventory.json"), JSON.stringify({
  qualified: false, platform, triplet, sources: lock,
  binarySha256: createHash("sha256").update(await readFile(executable)).digest("hex"),
  opensslConfigSha256: lock.opensslConfigSha256,
  vcpkgManifest: JSON.parse(await readFile(resolve(recipe, "vcpkg.json"), "utf8")),
  installedPackages: await readFile(resolve(build, "vcpkg_installed/vcpkg/status"), "utf8"),
}, null, 2) + "\n");
console.log(`Built unqualified native GPU candidate: ${executable}`);
