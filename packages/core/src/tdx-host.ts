export const TDX_SVN_FLOOR = "03010200000000000000000000000000";
export const TDX_COLLATERAL_FLOOR = 20;

/** Call only after authenticating the quote and both signed collateral documents. */
export function rateAuthenticatedTdxHost(status: string, svn: unknown, collateral: { tcb_info: string; qe_identity: string }): { host: 1 | 2; observed: string[] } {
  const observed = [`Intel ${status}`];
  let floors = false;
  try {
    const editions = [collateral.tcb_info, collateral.qe_identity].map(raw => JSON.parse(raw).tcbEvaluationDataNumber);
    if (svn instanceof Uint8Array) observed.push(`Authenticated TDX TCB SVN: ${Buffer.from(svn).toString("hex")}; collateral editions: ${editions.join(", ")}.`);
    floors = svn instanceof Uint8Array && svn.length === 16 && [...Buffer.from(TDX_SVN_FLOOR, "hex")].every((floor, index) => svn[index]! >= floor) &&
      editions.every(value => Number.isSafeInteger(value) && value >= TDX_COLLATERAL_FLOOR);
    if (!floors) observed.push("TDX SVN or verified collateral edition is below pi-tee's floors, or could not be read");
  } catch { observed.push("TDX floor values could not be read from verified evidence"); }
  return { host: status === "UpToDate" && floors ? 1 : 2, observed };
}
