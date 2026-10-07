import { readFile, stat } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { computeBootMeasurements } from "../../packages/tinfoil/src/boot-measurements.js";

try {
  let raw = "";
  for await (const chunk of process.stdin) { raw += chunk.toString(); if (raw.length > 16384) throw Error("input"); }
  const input = JSON.parse(raw);
  if (!input || Object.keys(input).sort().join(",") !== "cmdline,initrd,kernel,memoryMB" || typeof input.kernel !== "string" || typeof input.initrd !== "string" || !isAbsolute(input.kernel) || !isAbsolute(input.initrd)) throw Error("input");
  const read = async (path: string) => {
    const info = await stat(path);
    if (!info.isFile() || info.size > 32 * 1024 * 1024) throw Error("artifact");
    return readFile(path);
  };
  const [kernel, initrd] = await Promise.all([read(input.kernel), read(input.initrd)]);
  console.log(JSON.stringify(computeBootMeasurements(kernel, initrd, input.memoryMB, input.cmdline)));
} catch {
  console.log(JSON.stringify({ bootMeasurementsComputed: false, authenticatedBuild: false, inferenceQualified: false, failure: "TEE_BOOT_MEASUREMENT_REJECTED" }));
  process.exitCode = 1;
}
