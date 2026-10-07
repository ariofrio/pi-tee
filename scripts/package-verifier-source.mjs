import { readdir, copyFile, mkdir, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
const source = fileURLToPath(new URL("../tools/tinfoil-public-build/", import.meta.url));
const destination = fileURLToPath(new URL("../packages/tinfoil/verifier-source/", import.meta.url));
await rm(destination, { recursive: true, force: true });
await mkdir(destination);
for (const entry of await readdir(source, { withFileTypes: true })) {
  if (entry.isFile() && (["go.mod", "go.sum", "trusted_root.json"].includes(entry.name) || entry.name.endsWith(".go") && !entry.name.endsWith("_test.go"))) {
    await copyFile(resolve(source, entry.name), resolve(destination, entry.name));
  }
}
