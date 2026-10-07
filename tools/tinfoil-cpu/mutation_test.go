package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"testing"
)

func recomputeEnvelope(t *testing.T, d map[string]any, hashes map[string]any) {
	t.Helper()
	crypto, _ := base64.StdEncoding.DecodeString(d["crypto_material"].(string))
	device, _ := base64.StdEncoding.DecodeString(d["device_evidence"].(string))
	cryptoHash := sha256.Sum256(crypto)
	deviceHash := sha256.Sum256(device)
	hashes["crypto_material_hash"] = hex.EncodeToString(cryptoHash[:])
	hashes["device_evidence_hash"] = hex.EncodeToString(deviceHash[:])
	challenge := d["challenge"].(map[string]any)
	nonce, err := hex.DecodeString(challenge["nonce"].(string))
	if err != nil {
		t.Fatal(err)
	}
	reportData, err := envelope.ComputeReportData(nonce, cryptoHash[:], deviceHash[:])
	if err != nil {
		t.Fatal(err)
	}
	challenge["report_data"] = hex.EncodeToString(reportData[:])
}
