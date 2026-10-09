import { createHash, constants as cryptoConstants, verify as verifySignature, X509Certificate } from "node:crypto";
import { constants, getCollateral, INTEL_PCS_URL, verify, type Collateral } from "@phala/dcap-qvl";
import { rateAuthenticatedTdxHost, record, TeeError, withAbort } from "pi-tee-core";

export function base64(value: unknown, length?: number): Buffer {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new TeeError("TEE_ATTESTATION_REJECTED");
  const bytes = Buffer.from(value, "base64");
  if (!bytes.length || bytes.toString("base64") !== value || (length !== undefined && bytes.length !== length)) throw new TeeError("TEE_ATTESTATION_REJECTED");
  return bytes;
}

export interface CpuSeams {
  collateral?: (quote: Uint8Array) => Promise<Collateral>;
  verify?: typeof verify;
}

/** Authenticates the Chutes nonce/key commitment and its host-signed evidence envelope. */
export async function verifyChutesInstance(value: unknown, publicKey: string, nonce: string, signal: AbortSignal, seams: CpuSeams = {}) {
  try {
    signal.throwIfAborted();
    const evidence = record(value);
    if (evidence.tee_type !== "tdx" || !/^[a-f0-9]{64}$/.test(nonce)) throw new Error();
    base64(publicKey, 1184);
    const quote = base64(evidence.quote);
    if (quote.length < 636 || quote.readUInt16LE(0) !== 4 || quote.readUInt32LE(4) !== 0x81 ||
      quote.subarray(8, 12).some(byte => byte !== 0) || quote.subarray(12, 28).toString("hex") !== "939a7233f79c4ca9940a0db3957f0607") throw new Error();
    const end = 636 + quote.readUInt32LE(632);
    if (end > quote.length || quote.subarray(end).some(byte => byte !== 0)) throw new Error();
    // DER encoding of the same Intel root pinned by pi-tee's Go verifier.
    if (createHash("sha256").update(constants.TRUSTED_ROOT_CA_DER).digest("hex") !== "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3") throw new Error();
    const collateral = await withAbort((seams.collateral ?? (q => getCollateral(INTEL_PCS_URL, q)))(quote), signal);
    const checked = (seams.verify ?? verify)(quote, collateral, Math.floor(Date.now() / 1000));
    signal.throwIfAborted();
    const td = checked.report.asTd10();
    if (!td || !["UpToDate", "OutOfDate"].includes(checked.status) || Buffer.from(td.tdAttributes).toString("hex") !== "0000001000000000") throw new Error();
    const certificate = new X509Certificate(base64(evidence.certificate));
    const spki = certificate.publicKey.export({ type: "spki", format: "der" });
    const expected = Buffer.concat([createHash("sha256").update(nonce + publicKey).digest(), createHash("sha256").update(spki).digest()]);
    if (!expected.equals(Buffer.from(td.reportData))) throw new Error();
    if (certificate.publicKey.asymmetricKeyType !== "rsa" || (certificate.publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error();
    const body = base64(evidence.attested_body);
    if (!verifySignature("sha256", body, { key: certificate.publicKey, padding: cryptoConstants.RSA_PKCS1_PADDING }, base64(evidence.signature))) throw new Error();
    const signed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
    if (signed.nonce !== nonce || signed.evidence?.tdx_quote !== evidence.quote) throw new Error();
    const gpus = typeof signed.evidence?.nvtrust_evidence === "string" ? JSON.parse(signed.evidence.nvtrust_evidence) : signed.evidence?.nvtrust_evidence;
    if (!Array.isArray(gpus) || JSON.stringify(gpus) !== JSON.stringify(evidence.gpu_evidence)) throw new Error();
    return rateAuthenticatedTdxHost(checked.status, td.teeTcbSvn, collateral);
  } catch {
    signal.throwIfAborted();
    throw new TeeError("TEE_ATTESTATION_REJECTED");
  }
}
