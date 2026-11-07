package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

const deepseekRepo = "tinfoilsh/confidential-deepseek-v4-1-flash"

// Publishers tag per-GPU variants of one release with SemVer build metadata,
// signed by the same tagged release workflow. Pre-release and non-release tags
// stay outside the publisher identity.
func TestReleaseTagWithBuildMetadata(t *testing.T) {
	raw, err := os.ReadFile("testdata/deepseek-v0.0.10+b200.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := os.ReadFile("testdata/deepseek-v0.0.10+b200-deployment.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = requireCodeWorkflow(raw, deepseekRepo, "v0.0.10+b200"); err != nil {
		t.Fatalf("build-metadata release: %v", err)
	}
	code, subject, _, err := authenticateDeployment(deepseekRepo, "v0.0.10+b200", deployment, raw)
	if err != nil {
		t.Fatalf("build-metadata deployment: %v", err)
	}
	if code.Tag != "v0.0.10+b200" || subject.Firmware == nil || subject.Shape.GPUs != 4 {
		t.Fatalf("unexpected release: %s %+v", code.Tag, subject.Firmware)
	}
	for _, tag := range []string{"v0.0.10", "v0.0.10+b300", "v0.0.10-rc.1+b200"} {
		if requireCodeWorkflow(raw, deepseekRepo, tag) == nil {
			t.Fatalf("identity accepted for tag %s", tag)
		}
	}
	for _, tag := range []string{"v0.0.10-rc.1", "v0.0.10-rc.1+b200", "v0.0.10+", "v0.0.10+b200..x", "v0.0.10+b_200", "v0.0.10+b200/x", "b200-kernels-v1", "v0.0.10+" + strings.Repeat("a", 120)} {
		if isReleaseTag(tag) {
			t.Fatalf("release tag pattern admitted %q", tag)
		}
	}
	for _, tag := range []string{"v0.0.10+b200", "v0.0.9+b300-throughput", "v1.2.3+b.1"} {
		if !isReleaseTag(tag) {
			t.Fatalf("release tag pattern rejected %q", tag)
		}
	}
}

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
