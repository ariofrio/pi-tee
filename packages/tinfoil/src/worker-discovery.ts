import { readBoundedBody, record, TeeError, withAbort } from "pi-tee-core";

const deliveryUrls = [
  "https://inference.tinfoil.sh/.well-known/tinfoil-proxy",
  "https://router-0.tinfoil.sh/.well-known/tinfoil-proxy",
];

/** Untrusted discovery only. The selected worker still needs fresh hardware/build/key appraisal. */
export async function discoverTinfoilWorkers(options: {
  model: string; repository: string; signal: AbortSignal; fetch?: typeof globalThis.fetch;
}): Promise<{ host: string; claimedTag: string }[]> {
  const { model, repository, signal } = options;
  if (!/^[a-z0-9-]{1,100}$/.test(model) || !/^tinfoilsh\/[a-z0-9-]{1,150}$/.test(repository)) throw new TeeError("TEE_REQUEST_REJECTED");
  const hostPattern = /^[a-z0-9-]+-inf[0-9]+(?:-[0-9]+)?\.tinfoil\.containers\.tinfoil\.dev$/;
  for (const url of deliveryUrls) {
    signal.throwIfAborted();
    const bound = AbortSignal.any([signal, AbortSignal.timeout(5000)]);
    try {
      const response = await withAbort((options.fetch ?? globalThis.fetch)(url, { signal: bound, redirect: "error" }), bound);
      if (!response.ok) { await response.body?.cancel(); continue; }
      const bytes = await readBoundedBody(response.body, 2 * 1024 * 1024, bound);
      const status = record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
      const entry = record(record(status.models)[model]);
      if (entry.repo !== repository || typeof entry.tag !== "string" ||
          !/^v(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})$/.test(entry.tag)) continue;
      const hosts = Object.keys(record(entry.enclaves));
      if (!hosts.length || hosts.length > 128 || hosts.some(host => !hostPattern.test(host) || host.length > 253)) continue;
      signal.throwIfAborted();
      // Ignore delivery-supplied measurements and keys: they cannot authorize inference.
      return hosts.map(host => ({ host, claimedTag: entry.tag as string }));
    } catch { signal.throwIfAborted(); }
  }
  throw new TeeError("TEE_WORKER_DISCOVERY_UNAVAILABLE");
}
