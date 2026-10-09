import { snpMeetsFloors, tdxMeetsFloors } from "pi-tee-core";
/** Diagnostic decoding only, after the Contrast SDK authenticated these exact
 * protobuf bytes. Parsing never establishes authenticity or worker coverage. */
function fields(raw: Uint8Array): Map<number, bigint | Uint8Array> {
  let pos = 0;
  const values = new Map<number, bigint | Uint8Array>();
  function varint() {
    let n = 0n;
    for (let i = 0; i < 10 && pos < raw.length; i++) {
      const b = raw[pos++]!;
      n |= BigInt(b & 127) << BigInt(i * 7);
      if (!(b & 128)) return n;
    }
    throw Error("invalid protobuf");
  }
  while (pos < raw.length) {
    const tag = Number(varint()),
      field = tag >>> 3,
      wire = tag & 7;
    if (!field) throw Error("invalid field");
    if (wire === 0) values.set(field, varint());
    else if (wire === 2) {
      const length = Number(varint());
      if (!Number.isSafeInteger(length) || pos + length > raw.length)
        throw Error("invalid length");
      values.set(field, raw.slice(pos, (pos += length)));
    } else if (wire === 1 || wire === 5) {
      pos += wire === 1 ? 8 : 4;
      if (pos > raw.length) throw Error("invalid fixed field");
    } else throw Error("unsupported protobuf");
  }
  return values;
}
export function coordinatorFloorObservation(
  document: Record<string, unknown>,
  editions: readonly unknown[],
): string {
  try {
    const raw = fields(
      Buffer.from(document.raw_attestation_doc as string, "base64"),
    );
    const oid = (document.attestation_type as number[]).join(".");
    if (oid === "1.3.9901.2.2") {
      const td = fields(raw.get(2) as Uint8Array);
      return `Coordinator authenticated TDX floors: ${tdxMeetsFloors(td.get(1) as Uint8Array, editions) ? "met" : "below floor or incomplete"}; serving-worker floors and freshness remain unverified (H3).`;
    }
    if (oid === "1.3.9901.2.1") {
      const report = fields(raw.get(1) as Uint8Array);
      const n = (field: number) => Number(report.get(field) ?? 0n);
      const fms = n(29);
      const cpu = [
        ((fms >>> 8) & 15) + ((fms >>> 20) & 255),
        ((fms >>> 4) & 15) + ((fms >>> 12) & 240),
        fms & 15,
      ]
        .map((x) => x.toString(16).padStart(2, "0"))
        .join("/");
      const tcb = (field: number) => {
        const value = (report.get(field) as bigint) ?? 0n;
        const offsets = cpu.startsWith("1a/") ? [1, 2, 3, 7, 0] : [0, 1, 6, 7];
        return offsets.map((offset) =>
          Number((value >> BigInt(offset * 8)) & 255n),
        );
      };
      const provisional =
        [21, 22, 23].some((field, i) => n(field) !== n(24 + i)) ||
        report.get(8) !== report.get(20);
      const evidence = {
        cpu,
        build: n(21),
        api: [n(23), n(22)],
        provisional,
        current: tcb(8),
        launch: tcb(27),
      };
      const met =
        n(1) >= 3 &&
        snpMeetsFloors(evidence) &&
        snpMeetsFloors({ ...evidence, current: tcb(18), launch: tcb(20) });
      return `Coordinator authenticated SNP floors (${cpu}, build ${evidence.build}): ${met ? "met" : "below floor or incomplete"}; serving-worker floors and freshness remain unverified (H3).`;
    }
  } catch {
    /* Unknown/missing authenticated fields cannot establish floors. */
  }
  return "Coordinator floor values unavailable; serving-worker floors and freshness remain unverified (H3).";
}
