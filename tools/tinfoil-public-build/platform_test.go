package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"reflect"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPlatformReleaseAuthority(t *testing.T) {
	raw, err := os.ReadFile("testdata/platform-v0.1.0-classic.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := authenticatePlatform(raw, "tinfoilsh/cvmimage", "platform-v0.1.0", "0cba58535ac96b734d02f9ebd5db6e90f51c193e9d27c4432c8fc5a363f83d64", nil)
	if err != nil || p.Artifact == nil || p.Commit == "" {
		t.Fatalf("authentic public platform release: %v", err)
	}
	for _, tag := range []string{"v0.1.0", "platform-v01.1.0", "platform-v1.01.0", "platform-v1.0.01", "platform-v1.0.0-rc1", "platform-v1.0.0\n"} {
		if _, err := authenticatePlatform(raw, "tinfoilsh/cvmimage", tag, "0cba58535ac96b734d02f9ebd5db6e90f51c193e9d27c4432c8fc5a363f83d64", nil); err == nil {
			t.Fatal("accepted tag", tag)
		}
	}
	for _, tc := range []struct{ name, workflow, runner string }{{"wrong workflow", "release.yml", "github-hosted"}, {"self hosted", "platform-release.yml", "self-hosted"}} {
		t.Run(tc.name, func(t *testing.T) {
			changed := platformCertificateBundle(t, raw, tc.workflow, tc.runner)
			if _, _, err := platformIdentity(changed, cvmRepo, "platform-v0.1.0"); err == nil {
				t.Fatal("identity/runner gate accepted changed certificate")
			}
			if _, err := authenticatePlatform(changed, "tinfoilsh/cvmimage", "platform-v0.1.0", "0cba58535ac96b734d02f9ebd5db6e90f51c193e9d27c4432c8fc5a363f83d64", nil); err == nil {
				t.Fatal("accepted changed identity")
			}
		})
	}
}
func platformCertificateBundle(t *testing.T, raw []byte, workflow, runner string) []byte {
	t.Helper()
	var b map[string]any
	json.Unmarshal(raw, &b)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	san := "https://github.com/tinfoilsh/cvmimage/.github/workflows/" + workflow + "@refs/tags/platform-v0.1.0"
	u, _ := url.Parse(san)
	var original map[string]any
	json.Unmarshal(raw, &original)
	der, _ := base64.StdEncoding.DecodeString(original["verificationMaterial"].(map[string]any)["certificate"].(map[string]any)["rawBytes"].(string))
	cert, _ := x509.ParseCertificate(der)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), URIs: []*url.URL{u}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	for _, ext := range cert.Extensions {
		if strings.HasPrefix(ext.Id.String(), "1.3.6.1.4.1.57264.") {
			value := ext.Value
			if ext.Id.Equal(certificate.OIDRunnerEnvironment) {
				value, _ = asn1.Marshal(runner)
			}
			if ext.Id.Equal(certificate.OIDBuildSignerURI) {
				value, _ = asn1.Marshal(san)
			}
			template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: ext.Id, Value: value})
		}
	}
	changed, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	b["verificationMaterial"].(map[string]any)["certificate"].(map[string]any)["rawBytes"] = base64.StdEncoding.EncodeToString(changed)
	out, _ := json.Marshal(b)
	return out
}
func TestPlatformV2RequiresMatchedClassic(t *testing.T) {
	raw, _ := os.ReadFile("testdata/platform-v0.1.0-v2.bundle.json")
	classic, _ := os.ReadFile("testdata/platform-v0.1.0-classic.bundle.json")
	companion := &platformCompanion{Digest: "0cba58535ac96b734d02f9ebd5db6e90f51c193e9d27c4432c8fc5a363f83d64", Bundle: classic}
	p, err := authenticatePlatform(raw, "tinfoilsh/cvmimage", "platform-v0.1.0", "7fb88aa6336f6c53ee2be7b5ea074f39cc783da30aa6d296072c7bebbf59790d", companion)
	if err != nil || p.Artifact == nil || len(p.Artifact.Measurements) == 0 {
		t.Fatalf("v2 with authenticated classic: %v", err)
	}
	for _, c := range []*platformCompanion{nil, {Digest: strings.Repeat("0", 64), Bundle: classic}, {Digest: companion.Digest, Bundle: raw}} {
		if _, err := authenticatePlatform(raw, "tinfoilsh/cvmimage", "platform-v0.1.0", "7fb88aa6336f6c53ee2be7b5ea074f39cc783da30aa6d296072c7bebbf59790d", c); err == nil {
			t.Fatal("accepted missing/mismatched classic")
		}
	}
}

func TestPlatformV2SchemaAndBootConstraints(t *testing.T) {
	v2Bundle, _ := os.ReadFile("testdata/platform-v0.1.0-v2.bundle.json")
	classicBundle, _ := os.ReadFile("testdata/platform-v0.1.0-classic.bundle.json")
	runtime, _, err := authenticatePlatformStatement(v2Bundle, cvmRepo, "platform-v0.1.0", "7fb88aa6336f6c53ee2be7b5ea074f39cc783da30aa6d296072c7bebbf59790d")
	if err != nil {
		t.Fatal(err)
	}
	classic, _, err := authenticatePlatformStatement(classicBundle, cvmRepo, "platform-v0.1.0", "0cba58535ac96b734d02f9ebd5db6e90f51c193e9d27c4432c8fc5a363f83d64")
	if err != nil {
		t.Fatal(err)
	}
	merged, err := mergePlatformV2(runtime.Predicate, classic.Predicate)
	if err != nil {
		t.Fatal(err)
	}
	original, err := policy.Parse(classic.Predicate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(merged.Measurements, original.Measurements) || !reflect.DeepEqual(merged.Machines, original.Machines) {
		t.Fatal("changed classic boot measurements/machine inventory")
	}
	for name, p := range original.Policies {
		m := merged.Policies[name]
		if p.TDX != nil && !reflect.DeepEqual(p.TDX, m.TDX) {
			t.Fatal("changed TDX restrictions")
		}
		if p.SEVSNP != nil && p.SEVSNP.HostData != m.SEVSNP.HostData {
			t.Fatal("changed HOST_DATA")
		}
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"unknown root", func(p map[string]any) { p["unchecked"] = true }},
		{"unknown version", func(p map[string]any) { p["format"] = "https://tinfoil.sh/predicate/platform-endorsements/v3" }},
		{"unknown nested", func(p map[string]any) {
			p["policies"].(map[string]any)["tdx-b200-prod"].(map[string]any)["tdx"].(map[string]any)["unchecked"] = true
		}},
		{"missing policy field", func(p map[string]any) {
			delete(p["policies"].(map[string]any)["tdx-b200-prod"].(map[string]any)["tdx"].(map[string]any), "minimum_tee_tcb_svn")
		}},
		{"different machine", func(p map[string]any) {
			p["machines"].(map[string]any)["2cc554da2e91064c548f0cb0e305647c"] = "tdx-h200-prod"
		}},
		{"boot field in v2", func(p map[string]any) {
			p["policies"].(map[string]any)["amd-genoa-prod"].(map[string]any)["sev_snp"].(map[string]any)["host_data"] = strings.Repeat("0", 64)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p map[string]any
			json.Unmarshal(runtime.Predicate, &p)
			tc.change(p)
			changed, _ := json.Marshal(p)
			if _, err := mergePlatformV2(changed, classic.Predicate); err == nil {
				t.Fatal("accepted inconsistent v2 schema")
			}
		})
	}
	duplicate := append([]byte(`{"format":"https://tinfoil.sh/predicate/platform-endorsements/v2",`), runtime.Predicate[1:]...)
	if _, err := mergePlatformV2(duplicate, classic.Predicate); err == nil {
		t.Fatal("accepted duplicate member")
	}
}
