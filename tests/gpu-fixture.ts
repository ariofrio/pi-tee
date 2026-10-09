export function report(mode: number) {
  const request = Buffer.alloc(37);
  request[0] = 0x11; request[1] = 0xe0;
  const response = Buffer.alloc(8);
  response[0] = 0x11; response[1] = 0x60; response[4] = 1;
  response.writeUIntLE(7, 5, 3);
  const opaque = Buffer.from([34, 0, 2, 0, 1, 0, 36, 0, 2, 0, mode, 0]);
  const length = Buffer.alloc(2); length.writeUInt16LE(opaque.length);
  return Buffer.concat([request, response, Buffer.alloc(7), Buffer.alloc(32), length, opaque, Buffer.alloc(96)]).toString("base64");
}
export const nonce = "ab".repeat(32);
export const chain = { "x-nvidia-cert-status": "valid", "x-nvidia-cert-ocsp-status": "good", "x-nvidia-cert-ocsp-response-valid": true, "x-nvidia-cert-ocsp-nonce-matches": true };
export function claim(index: number, hwmodel = "GB110 A01 GSP BROM", vbios = "97.10.64.00.0C") {
  return {
    eat_nonce: nonce, hwmodel, measres: "success", dbgstat: "disabled", secboot: true, ueid: `device-${index}`,
    "x-nvidia-gpu-driver-version": "595.71.05", "x-nvidia-gpu-vbios-version": vbios,
    "x-nvidia-gpu-attestation-report-cert-chain": chain, "x-nvidia-gpu-driver-rim-cert-chain": chain, "x-nvidia-gpu-vbios-rim-cert-chain": chain,
    ...Object.fromEntries([
      "x-nvidia-gpu-arch-check", "x-nvidia-gpu-attestation-report-parsed", "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
      "x-nvidia-gpu-driver-rim-fetched", "x-nvidia-gpu-driver-rim-measurements-available", "x-nvidia-gpu-driver-rim-signature-verified",
      "x-nvidia-gpu-driver-rim-version-match", "x-nvidia-gpu-vbios-rim-fetched", "x-nvidia-gpu-vbios-rim-measurements-available",
      "x-nvidia-gpu-vbios-rim-signature-verified", "x-nvidia-gpu-vbios-rim-version-match", "x-nvidia-gpu-vbios-index-no-conflict",
      "x-nvidia-gpu-attestation-report-signature-verified", "x-nvidia-gpu-attestation-report-nonce-match",
    ].map(name => [name, true])),
  };
}
export function verdict(claims: unknown[]) { return { code: 0, stdout: JSON.stringify({ result_code: 0, claims }) }; }
