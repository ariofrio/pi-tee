export const GPU_VERSION_FLOORS = Object.freeze({ driver: "595.71.05", vbios: "96.00.D9.00.02" });

function atLeast(value: number[], floor: number[]): boolean {
  for (let index = 0; index < floor.length; index++) {
    if (value[index] !== floor[index]) return value[index]! > floor[index]!;
  }
  return true;
}

// Version floors supplement manufacturer signatures, reference matching and
// revocation. They are neither signatures nor a global firmware security rank.
export function gpuVersionsAllowed(driver: unknown, vbios: unknown, policy: "public-builds" | "frozen"): boolean {
  if (typeof driver !== "string" || typeof vbios !== "string") return false;
  if (policy === "frozen") return driver === GPU_VERSION_FLOORS.driver && vbios === GPU_VERSION_FLOORS.vbios;
  if (policy !== "public-builds" || !/^[1-9][0-9]{2,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(driver) || !/^[a-fA-F0-9]{2}(\.[a-fA-F0-9]{2}){4}$/.test(vbios)) return false;
  return atLeast(driver.split(".").map(Number), [595, 71, 5]) && atLeast(vbios.split(".").map(part => Number.parseInt(part, 16)), [0x96, 0, 0xd9, 0, 2]);
}
