import { getCollateral, INTEL_PCS_URL, verify, type Collateral } from "@phala/dcap-qvl";
import { rateAuthenticatedTdxHost, TeeError, withAbort } from "pi-tee-core";
import type { TdxQuoteVerifier } from "@nearai/inference-sdk/node";

export interface NearHostRating { host: 1 | 2; observed: string[] }

/** The same SVN and collateral-edition floors as floorTDXArtifact. */
export function createNearCpuVerifier(options: {
  signal?: AbortSignal;
  onRating: (rating: NearHostRating) => void;
  collateral?: typeof getCollateral;
  verify?: typeof verify;
}): TdxQuoteVerifier {
  return async quote => {
    if (!/^(?:[a-fA-F0-9]{2})+$/.test(quote)) throw new TeeError("TEE_CPU_POLICY_REJECTED");
    const bytes = Buffer.from(quote, "hex");
    const signal = options.signal ?? AbortSignal.timeout(60000);
    const collateral: Collateral = await withAbort((options.collateral ?? getCollateral)(INTEL_PCS_URL, bytes), signal);
    const checked = (options.verify ?? verify)(bytes, collateral, Math.floor(Date.now() / 1000));
    const td = checked.report.asTd10();
    if (!td) throw new TeeError("TEE_CPU_POLICY_REJECTED");
    options.onRating(rateAuthenticatedTdxHost(checked.status, td.teeTcbSvn, collateral));
    return { tcbStatus: checked.status, advisoryIds: checked.advisory_ids, debugEnabled: !!(td.tdAttributes[0]! & 1), reportData: td.reportData, mrConfigId: td.mrConfigId, rtMr3: td.rtMr3 };
  };
}
