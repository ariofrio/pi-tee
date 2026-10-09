package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

const routerDigest = "ad95d02b2e27b3c1d5c327f2ee9616634f841e4b2ed5a48f404e4e9f595a4876"

// The router and model publishers share one workflow shape; neither mode may admit the other.
func TestRouterReleaseIdentity(t *testing.T) {
	router, err := os.ReadFile("testdata/router-v0.0.155.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	gemma, err := os.ReadFile("testdata/gemma-v0.0.25.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = requireReleaseWorkflow(router, routerRepo, "v0.0.155", true); err != nil {
		t.Fatalf("router release: %v", err)
	}
	if _, err = provenance.AuthenticateCode(router, routerRepo, "v0.0.155", routerDigest); err != nil {
		t.Fatalf("router signature: %v", err)
	}
	if requireReleaseWorkflow(router, routerRepo, "v0.0.155", false) == nil || requireCodeWorkflow(router, routerRepo, "v0.0.155") == nil {
		t.Fatal("router release admitted as a model publisher")
	}
	if requireReleaseWorkflow(gemma, "tinfoilsh/confidential-gemma4-31b", "v0.0.25", true) == nil {
		t.Fatal("model release admitted as the router")
	}
	if requireReleaseWorkflow(router, routerRepo, "v0.0.156", true) == nil {
		t.Fatal("router identity accepted for another tag")
	}
}

// Fresh router evidence from /.well-known/tinfoil-attestation, wrapped as
// {"nonce","allowOutdated","envelope"}.
func TestRouterEvidence(t *testing.T) {
	path := os.Getenv("PI_TEE_ROUTER_TEST_EVIDENCE")
	if path == "" {
		t.Skip("set PI_TEE_ROUTER_TEST_EVIDENCE to fresh public router evidence")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if runMode(bytes.NewReader(raw), &out, time.Now(), true) != 0 {
		t.Fatalf("authentic router evidence: %s", out.String())
	}
	var result map[string]any
	if err = json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["repo"] != routerRepo || result["platform"] != "sev-snp" || result["cpuVerified"] != true || result["inferenceQualified"] != false {
		t.Fatalf("unexpected router result: %s", out.String())
	}
	out.Reset()
	if run(bytes.NewReader(raw), &out, time.Now()) == 0 {
		t.Fatal("model mode admitted the router")
	}
	var nonce map[string]any
	_ = json.Unmarshal(raw, &nonce)
	nonce["nonce"] = "0101010101010101010101010101010101010101010101010101010101010101"
	replayed, _ := json.Marshal(nonce)
	out.Reset()
	if runMode(bytes.NewReader(replayed), &out, time.Now(), true) == 0 {
		t.Fatal("router mode accepted a replayed nonce")
	}
}
