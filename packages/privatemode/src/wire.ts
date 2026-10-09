import { TeeError } from "pi-tee-core";
export const PRIVATEMODE_BASE_URL = "https://api.privatemode.ai/v1";
export const ENCRYPTED_BODY = "application/vnd.privatemode.encrypted-body";
const apiPaths = new Set([
  "/privatemode/v1/attest",
  "/privatemode/v1/secret",
  "/v1/chat/completions",
]);
const metadataHeaders = new Set([
  "authorization",
  "content-type",
  "accept",
  "privatemode-version",
  "privatemode-client",
  "privatemode-secret-id",
  "privatemode-target-model",
  "privatemode-shard-key",
  "privatemode-content-length-tokens",
  "privatemode-oae-request-header",
  "x-request-id",
  "privatemode-user-request-id",
]);
// Runtime fetch may add User-Agent/accept-* headers after this SDK-header guard;
// they are ordinary gateway-visible metadata, not attested request fields.
/** Final network boundary: TLS-only API, fixed paths, full encrypted body and
 * bounded metadata. Manufacturer collateral requests carry no credentials. */
export function guardPrivatemodeWire(
  request: Request,
  model: string,
  apiKey: string,
  inferenceAllowed: boolean,
) {
  const url = new URL(request.url);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    (url.port && url.port !== "443")
  )
    throw new TeeError("TEE_REQUEST_REJECTED");
  if (url.hostname === "api.privatemode.ai") {
    if (
      !apiPaths.has(url.pathname) ||
      url.search ||
      request.method !== "POST" ||
      request.headers.get("authorization") !== `Bearer ${apiKey}`
    )
      throw new TeeError("TEE_REQUEST_REJECTED");
    for (const [name] of request.headers)
      if (!metadataHeaders.has(name))
        throw new TeeError("TEE_REQUEST_REJECTED");
    if (
      url.pathname === "/v1/chat/completions" &&
      (!inferenceAllowed ||
        request.headers.get("content-type") !== ENCRYPTED_BODY ||
        !/^:[A-Za-z0-9+/]+=*:$/.test(
          request.headers.get("privatemode-oae-request-header") ?? "",
        ) ||
        request.headers.get("privatemode-target-model") !== model)
    )
      throw new TeeError("TEE_REQUEST_REJECTED");
  } else {
    const collateral =
      (url.hostname === "kdsintf.amd.com" &&
        /^\/vcek\/v1\/(Genoa|Turin|Milan)\//.test(url.pathname)) ||
      (url.hostname === "api.trustedservices.intel.com" &&
        /^\/tdx\/certification\/v4\//.test(url.pathname)) ||
      (url.hostname === "api.trustedservices.intel.com" &&
        /^\/sgx\/certification\/v4\//.test(url.pathname));
    if (
      !collateral ||
      request.method !== "GET" ||
      request.headers.has("authorization")
    )
      throw new TeeError("TEE_REQUEST_REJECTED");
  }
}
