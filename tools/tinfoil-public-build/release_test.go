package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

// The firmware member is decoded strictly, like every other predicate member.
func TestFirmwareMemberIsStrict(t *testing.T) {
	raw, err := os.ReadFile("testdata/router-v0.0.171.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := os.ReadFile("testdata/router-v0.0.171-deployment.json")
	if err != nil {
		t.Fatal(err)
	}
	code, err := provenance.AuthenticateCode(raw, routerRepo, "v0.0.171", digest256(deployment))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(map[string]any){
		"unknown firmware member": func(f map[string]any) { f["tdx"] = map[string]any{} },
		"unknown SEV-SNP member":  func(f map[string]any) { f["sev_snp"].(map[string]any)["url"] = "x" },
		"case variant":            func(f map[string]any) { f["SEV_SNP"] = f["sev_snp"] },
		"other firmware type":     func(f map[string]any) { f["sev_snp"].(map[string]any)["type"] = "igvm" },
		"malformed digest":        func(f map[string]any) { f["sev_snp"].(map[string]any)["sha256"] = "78C8" },
		"malformed version":       func(f map[string]any) { f["sev_snp"].(map[string]any)["version"] = "latest" },
		"no SEV-SNP firmware":     func(f map[string]any) { delete(f, "sev_snp") },
	} {
		t.Run(name, func(t *testing.T) {
			var b bundle.Bundle
			if err := b.UnmarshalJSON(raw); err != nil {
				t.Fatal(err)
			}
			var statement map[string]any
			if err := json.Unmarshal(b.GetDsseEnvelope().GetPayload(), &statement); err != nil {
				t.Fatal(err)
			}
			change(statement["predicate"].(map[string]any)["firmware"].(map[string]any))
			payload, _ := json.Marshal(statement)
			var outer map[string]any
			_ = json.Unmarshal(raw, &outer)
			outer["dsseEnvelope"].(map[string]any)["payload"] = base64.StdEncoding.EncodeToString(payload)
			changed, _ := json.Marshal(outer)
			if _, _, err := codePredicate(changed, code); err == nil {
				t.Fatal("accepted a malformed firmware member")
			}
		})
	}
}
