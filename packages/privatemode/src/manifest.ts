import { createHash } from "node:crypto";
import { readFile, mkdir, appendFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { TeeError, fetchUpstream, readBoundedBody } from "pi-tee-core";

export interface AdmittedManifest {
  bytes: Uint8Array;
  sha256: string;
  source: string;
}
/** Local software-admission authority. A public log/reproduced pin can implement
 * this interface later; it cannot by itself raise a route above A2. */
export interface ManifestAdmissionPolicy {
  admit(signal: AbortSignal): Promise<AdmittedManifest>;
}
export const MANIFEST_SHA256 =
  "384a2137e534357d74392bf3940373ff49d309d91551376b5a7f828e372af42b";
export function createPinnedManifestPolicy(
  bytes: Uint8Array,
  sha256: string,
  source: string,
): ManifestAdmissionPolicy {
  const pin = Uint8Array.from(bytes);
  if (createHash("sha256").update(pin).digest("hex") !== sha256)
    throw new TeeError("TEE_WORKLOAD_PIN_REJECTED");
  return {
    async admit(signal) {
      signal.throwIfAborted();
      return { bytes: Uint8Array.from(pin), sha256, source };
    },
  };
}
export const shippedManifestPolicy: ManifestAdmissionPolicy = {
  async admit(signal) {
    const bytes = await readFile(
      new URL("../manifests/v1.58.0.json", import.meta.url),
    );
    return createPinnedManifestPolicy(
      bytes,
      MANIFEST_SHA256,
      "pi-tee:privatemode/v1.58.0",
    ).admit(signal);
  },
};
export const MANIFEST_CDN_URL =
  "https://cdn.confidential.cloud/privatemode/v2/manifest.json";
export function createRecordedCdnManifestPolicy(options: {
  fetch?: typeof globalThis.fetch;
  record: (manifest: AdmittedManifest, signal: AbortSignal) => Promise<void>;
}): ManifestAdmissionPolicy {
  return {
    async admit(signal) {
      const response = await fetchUpstream(
        options.fetch ?? globalThis.fetch,
        MANIFEST_CDN_URL,
        { signal, redirect: "error" },
        "evidence",
        "TEE_WORKLOAD_PIN_REJECTED",
      );
      if (
        response.redirected ||
        (response.url && response.url !== MANIFEST_CDN_URL)
      )
        throw new TeeError("TEE_WORKLOAD_PIN_REJECTED");
      const bytes = await readBoundedBody(response.body, 1024 * 1024, signal);
      const parsed = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
      if (
        !parsed ||
        typeof parsed.Policies !== "object" ||
        !parsed.Policies ||
        Array.isArray(parsed.Policies)
      )
        throw new TeeError("TEE_WORKLOAD_PIN_REJECTED");
      const manifest = {
        bytes,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        source: MANIFEST_CDN_URL,
      };
      await options.record(manifest, signal);
      signal.throwIfAborted();
      return manifest;
    },
  };
}
export function manifestPolicyFromEnvironment(
  record: (manifest: AdmittedManifest, signal: AbortSignal) => Promise<void>,
): ManifestAdmissionPolicy {
  const mode = process.env.PI_PRIVATEMODE_MANIFEST_MODE ?? "hard-pin";
  const path = process.env.PI_PRIVATEMODE_MANIFEST_PATH;
  if (mode === "logged-cdn" && !path)
    return createRecordedCdnManifestPolicy({ record });
  if (mode !== "hard-pin") throw new TeeError("TEE_WORKLOAD_PIN_REJECTED");
  if (!path) return shippedManifestPolicy;
  let pin: Promise<ManifestAdmissionPolicy> | undefined;
  return {
    async admit(signal) {
      pin ??= readFile(path).then((bytes) =>
        createPinnedManifestPolicy(
          bytes,
          createHash("sha256").update(bytes).digest("hex"),
          `file:${path}`,
        ),
      );
      return (await pin).admit(signal);
    },
  };
}
export function manifestRecorder(
  path = join(
    process.env.XDG_STATE_HOME ?? join(homedir(), ".local/state"),
    "pi-tee/privatemode/manifest-admissions.jsonl",
  ),
) {
  let previous: string | undefined;
  let previousSource: string | undefined;
  let loaded = false;
  let queue = Promise.resolve();
  return (manifest: AdmittedManifest, signal: AbortSignal) => {
    queue = queue
      .catch(() => undefined)
      .then(async () => {
        signal.throwIfAborted();
        if (!loaded) {
          try {
            const rows = (await readFile(path, "utf8"))
              .trim()
              .split("\n")
              .filter(Boolean);
            if (rows.length) {
              const last = JSON.parse(rows.at(-1)!);
              if (
                typeof last.sha256 !== "string" ||
                !/^[a-f0-9]{64}$/.test(last.sha256)
              )
                throw Error("invalid admission journal");
              previous = last.sha256;
              previousSource = last.source;
            }
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          }
          loaded = true;
        }
        if (previous === manifest.sha256 && previousSource === manifest.source) return;
        await mkdir(dirname(path), { recursive: true, mode: 0o700 });
        await appendFile(
          path,
          JSON.stringify({
            version: 1,
            previous: previous ?? null,
            sha256: manifest.sha256,
            source: manifest.source,
            adoptedAt: new Date().toISOString(),
          }) + "\n",
          { mode: 0o600 },
        );
        previous = manifest.sha256;
        previousSource = manifest.source;
      });
    return queue;
  };
}
