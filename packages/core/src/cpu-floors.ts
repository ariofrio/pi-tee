export { tdxMeetsFloors } from "./tdx-host.js";

/** CPUID/TCB minima from tools/tinfoil-public-build/release.go's snpFloors.
 * TCB order is bootloader, TEE, SNP, microcode, optional Turin FMC. */
const SNP_FLOORS: Record<string, { build: number; api: readonly number[]; tcb: readonly number[] }> = {
  "19/11/01": { build: 21, api: [1, 55], tcb: [7, 0, 27, 86] },
  "19/11/02": { build: 21, api: [1, 55], tcb: [7, 0, 27, 81] },
  "1a/02/01": { build: 0, api: [1, 58], tcb: [1, 1, 4, 81, 1] },
};
export function snpMeetsFloors(evidence: {
  cpu: string; build: number; api: readonly number[]; provisional: boolean;
  current: readonly number[]; launch: readonly number[];
}): boolean {
  const floor = SNP_FLOORS[evidence.cpu];
  const numbers = [evidence.build, ...evidence.api, ...evidence.current, ...evidence.launch];
  return !!floor && numbers.every(n => Number.isSafeInteger(n) && n >= 0 && n <= 255) && !evidence.provisional &&
    evidence.build >= floor.build && evidence.api.length === 2 &&
    (evidence.api[0]! > floor.api[0]! || evidence.api[0] === floor.api[0] && evidence.api[1]! >= floor.api[1]!) &&
    [evidence.current, evidence.launch].every(tcb => tcb.length === floor.tcb.length && floor.tcb.every((min, i) => tcb[i]! >= min));
}
