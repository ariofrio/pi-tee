import { getCollateral, INTEL_PCS_URL, verify, type Collateral } from "@phala/dcap-qvl";
import { TeeError, withAbort } from "pi-tee-core";
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
    const observed = [`Intel ${checked.status}`];
    let floors = false;
    try {
      const svn = td.teeTcbSvn;
      const editions = [collateral.tcb_info, collateral.qe_identity].map(raw => JSON.parse(raw).tcbEvaluationDataNumber);
      if (svn instanceof Uint8Array) observed.push(`Authenticated TDX TCB SVN: ${Buffer.from(svn).toString("hex")}; collateral editions: ${editions.join(", ")}.`);
      floors = svn instanceof Uint8Array && svn.length === 16 && [3, 1, 2].every((floor, index) => svn[index]! >= floor) &&
        editions.every(value => Number.isSafeInteger(value) && value >= 20);
      if (!floors) observed.push("TDX SVN or verified collateral edition is below pi-tee's floors, or could not be read");
    } catch { observed.push("TDX floor values could not be read from verified evidence"); }
    options.onRating({ host: checked.status === "UpToDate" && floors ? 1 : 2, observed });
    return { tcbStatus: checked.status, advisoryIds: checked.advisory_ids, debugEnabled: !!(td.tdAttributes[0]! & 1), reportData: td.reportData, mrConfigId: td.mrConfigId, rtMr3: td.rtMr3 };
  };
}
