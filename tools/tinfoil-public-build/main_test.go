package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRejectInvalidInput(t *testing.T) {
	for _, raw := range []string{`{}`, `{"nonce":"00","envelope":{}}`, `{} {}`, `{"allowUnverified":true}`, strings.Repeat(" ", maxInputBytes+1)} {
		var out bytes.Buffer
		if run(bytes.NewBufferString(raw), &out, time.Now()) == 0 {
			t.Fatal("accepted invalid verification input")
		}
	}
}

// This exercises the command's evidence boundary with real signatures, not a verifier mock.
func TestPublicBuildEvidence(t *testing.T) {
	path := os.Getenv("PI_TEE_PUBLIC_BUILD_TEST_EVIDENCE")
	if path == "" {
		t.Skip("set PI_TEE_PUBLIC_BUILD_TEST_EVIDENCE to fresh public TDX evidence")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var out bytes.Buffer
	if run(bytes.NewReader(raw), &out, now) != 0 {
		t.Fatalf("authentic evidence: %s", out.String())
	}
	var result map[string]any
	if err = json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["cpuVerified"] != true || result["publicBuildVerified"] != true || result["inferenceQualified"] != false {
		t.Fatal("incorrect verification scope")
	}
	if result["repo"] != "tinfoilsh/confidential-gemma4-31b" || result["workflow"] != "tinfoil-release-publish.yml" {
		t.Fatal("unexpected release authority")
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		time   time.Time
	}{
		{"replay nonce", func(d map[string]any) {
			d["nonce"] = "0101010101010101010101010101010101010101010101010101010101010101"
		}, now},
		{"missing provenance", func(d map[string]any) { d["envelope"].(map[string]any)["collateral"] = []any{} }, now},
		{"stale witness", func(d map[string]any) {}, now.Add(8 * 24 * time.Hour)},
		{"future witness", func(d map[string]any) {}, now.Add(-8 * 24 * time.Hour)},
		{"substituted digest", func(d map[string]any) {
			for _, c := range d["envelope"].(map[string]any)["collateral"].([]any) {
				m := c.(map[string]any)
				if m["id"] == "code" {
					m["data"].(map[string]any)["digest"] = "0000000000000000000000000000000000000000000000000000000000000000"
				}
			}
		}, now},
		{"substituted repository", func(d map[string]any) {
			for _, c := range d["envelope"].(map[string]any)["collateral"].([]any) {
				m := c.(map[string]any)
				if m["id"] == "code" {
					m["data"].(map[string]any)["repo"] = "attacker/confidential-gemma4-31b"
				}
			}
		}, now},
		{"substituted release tag", func(d map[string]any) {
			for _, c := range d["envelope"].(map[string]any)["collateral"].([]any) {
				m := c.(map[string]any)
				if m["id"] == "code" {
					m["data"].(map[string]any)["tag"] = "v999.0.0"
				}
			}
		}, now},
		{"forged software statement", func(d map[string]any) {
			for _, c := range d["envelope"].(map[string]any)["collateral"].([]any) {
				m := c.(map[string]any)
				if m["id"] == "code" {
					b := m["data"].(map[string]any)["sigstore_bundle"].(map[string]any)["dsseEnvelope"].(map[string]any)
					payload, _ := base64.StdEncoding.DecodeString(b["payload"].(string))
					payload[0] ^= 1
					b["payload"] = base64.StdEncoding.EncodeToString(payload)
				}
			}
		}, now},
		{"missing software freshness", func(d map[string]any) {
			outer := d["envelope"].(map[string]any)
			kept := []any{}
			for _, c := range outer["collateral"].([]any) {
				if c.(map[string]any)["id"] != "code-freshness" {
					kept = append(kept, c)
				}
			}
			outer["collateral"] = kept
		}, now},
		{"forged CPU signature", func(d map[string]any) {
			cpu := d["envelope"].(map[string]any)["cpu_evidence"].(map[string]any)
			raw, _ := base64.StdEncoding.DecodeString(cpu["report_base64"].(string))
			raw[584] ^= 1
			cpu["report_base64"] = base64.StdEncoding.EncodeToString(raw)
		}, now},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d map[string]any
			if err := json.Unmarshal(raw, &d); err != nil {
				t.Fatal(err)
			}
			tc.change(d)
			changed, _ := json.Marshal(d)
			var out bytes.Buffer
			if run(bytes.NewReader(changed), &out, tc.time) == 0 {
				t.Fatal("accepted tampered evidence")
			}
			var rejection map[string]any
			if err := json.Unmarshal(out.Bytes(), &rejection); err != nil {
				t.Fatal(err)
			}
			if rejection["cpuVerified"] != false || rejection["inferenceQualified"] != false {
				t.Fatal("overclaimed rejection")
			}
		})
	}
}
