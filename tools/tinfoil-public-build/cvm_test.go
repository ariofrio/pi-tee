package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// The command boundary uses a public, signed GitHub build bundle. No CPU quote,
// provider credential, prompt or mocked cryptographic verifier is involved.
func TestPublicCVMBuild(t *testing.T) {
	manifest, err := os.ReadFile("testdata/cvm-v0.11.0-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile("testdata/cvm-v0.11.0.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"tag": "v0.11.0", "manifest": base64.StdEncoding.EncodeToString(manifest), "bundle": json.RawMessage(bundle)}
	raw, _ := json.Marshal(input)
	var out bytes.Buffer
	if runCVM(bytes.NewReader(raw), &out) != 0 {
		t.Fatalf("authentic public CVM build: %s", out.String())
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["cvmBuildVerified"] != true || result["inferenceQualified"] != false ||
		result["commit"] != "a4dbce07f5b0efbee1df678026db538eba66a613" ||
		result["manifestDigest"] != "a7560566ca6c533f8391d3fc41df966d893b2f1d0ac7da04af8efa18ab9067f8" {
		t.Fatalf("incorrect authenticated build scope: %s", out.String())
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"substituted tag", func(i map[string]any) { i["tag"] = "v0.11.1" }},
		{"branch ref", func(i map[string]any) { i["tag"] = "main" }},
		{"changed manifest bytes", func(i map[string]any) {
			i["manifest"] = base64.StdEncoding.EncodeToString(append(append([]byte{}, manifest...), '\n'))
		}},
		{"forged build statement", func(i map[string]any) {
			var b map[string]any
			json.Unmarshal(bundle, &b)
			dsse := b["dsseEnvelope"].(map[string]any)
			payload, _ := base64.StdEncoding.DecodeString(dsse["payload"].(string))
			payload = bytes.ReplaceAll(payload, []byte("cvmimage"), []byte("evilrepo"))
			dsse["payload"] = base64.StdEncoding.EncodeToString(payload)
			i["bundle"] = b
		}},
		{"absent build evidence", func(i map[string]any) { i["bundle"] = map[string]any{} }},
		{"caller-selected authority", func(i map[string]any) { i["repo"] = "attacker/cvmimage" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var i map[string]any
			if err := json.Unmarshal(raw, &i); err != nil {
				t.Fatal(err)
			}
			tc.change(i)
			changed, _ := json.Marshal(i)
			var out bytes.Buffer
			if runCVM(bytes.NewReader(changed), &out) == 0 {
				t.Fatal("accepted substituted public build")
			}
			var r map[string]any
			if json.Unmarshal(out.Bytes(), &r) != nil || r["cvmBuildVerified"] != false || r["inferenceQualified"] != false {
				t.Fatalf("incorrect rejected scope: %s", out.String())
			}
		})
	}
}
