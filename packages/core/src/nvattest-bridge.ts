// NVIDIA's verifier fetches signed reference manifests and OCSP responses. The
// bridge admits only those two public services, bounded and without redirects
// or credentials; the signatures, not delivery, authenticate the bytes.
const RIM = "https://rim.attestation.nvidia.com";
const OCSP = "https://ocsp.ndis.nvidia.com";
const FORWARDED_HEADERS = new Set(["accept", "content-type", "x-request-id"]);
const MAX_REQUESTS = 192;

async function bounded(response: Response, limit: number) {
  const reader = response.body!.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const next = await reader.read();
    if (next.done) break;
    size += next.value.length;
    if (size > limit) { await reader.cancel(); throw Error("response too large"); }
    chunks.push(next.value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}

/** Returns the request function the NVIDIA verifier's HTTP client calls. Tests may add one loopback relay origin. */
export function nvidiaCollateralBridge(options: { collateralOrigin?: string; fetch?: typeof globalThis.fetch; rims?: Record<string, Uint8Array>; onRim?: (id: string, body: Uint8Array) => void } = {}) {
  const { collateralOrigin, fetch = globalThis.fetch } = options;
  // Reference manifests are signed and named by version; the verifier checks each copy.
  const rims = new Map<string, Promise<{ status: number; body: Uint8Array }>>(Object.entries(options.rims ?? {}).map(([id, body]) => [id, Promise.resolve({ status: 200, body })]));
  let requests = 0;
  return async function request(method: string, url: string, headers: Record<string, unknown>, body: Uint8Array<ArrayBuffer>) {
    if (++requests > MAX_REQUESTS) throw Error("too many requests");
    const target = new URL(url);
    const origin = (service: string) => target.origin === service || (collateralOrigin !== undefined && target.origin === collateralOrigin);
    const rim = method === "GET" && origin(RIM) && /^\/v1\/rim\/[A-Za-z0-9._-]{1,160}$/.test(target.pathname);
    const ocsp = method === "POST" && origin(OCSP) && (target.pathname === "/" || target.pathname === "/ocsp");
    if ((!rim && !ocsp) || target.search || target.hash || target.username || target.password) throw Error("destination rejected");
    if (rim) {
      const id = `${target.origin}${target.pathname}`;
      let cached = rims.get(id);
      if (!cached) {
        cached = send(target, method, headers, body, true).then(result => { if (result.status === 200) options.onRim?.(id, result.body); else rims.delete(id); return result; });
        cached.catch(() => rims.delete(id));
        rims.set(id, cached);
      }
      const { status, body: bytes } = await cached;
      return { status, body: bytes.slice() };
    }
    return send(target, method, headers, body, false);
  };
  async function send(target: URL, method: string, headers: Record<string, unknown>, body: Uint8Array<ArrayBuffer>, rim: boolean) {
    const forwarded = Object.fromEntries(Object.entries(headers).filter(([name, value]) => FORWARDED_HEADERS.has(name.toLowerCase()) && typeof value === "string")) as Record<string, string>;
    const response = await fetch(target, { method, headers: forwarded, body: rim ? undefined : body, redirect: "error", signal: AbortSignal.timeout(15000) });
    if (!response.body) throw Error("missing body");
    return { status: response.status, body: await bounded(response, rim ? 4 * 1024 * 1024 : 65536) };
  }
}
