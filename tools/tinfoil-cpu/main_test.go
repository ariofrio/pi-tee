package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

func TestInputBounds(t *testing.T) {
	for _, input := range []string{
		`{"nonce":"00","envelope":{}}`,
		`{"nonce":"` + strings.Repeat("00", 32) + `","envelope":{},"allowOutdated":true}`,
		`{"nonce":"` + strings.Repeat("00", 32) + `","envelope":{}} {}`,
		strings.Repeat(" ", maxInputBytes+1),
	} {
		if _, _, err := decodeInput(strings.NewReader(input)); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
}

// The fixture is fetched separately. No credentials or raw machine quote are committed.
func TestLiveAuthenticQuote(t *testing.T) {
	path := os.Getenv("PI_TEE_CPU_TEST_EVIDENCE")
	if path == "" {
		t.Skip("set PI_TEE_CPU_TEST_EVIDENCE to a fresh public evidence file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	input, nonce, err := decodeInput(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	// A snapshot of the observed machine's weaker levels establishes a real positive
	// crypto/binding control. The CLI never offers this policy.
	var baselineManifest manifest
	if err = json.Unmarshal(localPolicyBytes(), &baselineManifest); err != nil {
		t.Fatal(err)
	}
	cpu := baselineManifest.CPU.SEVSNP
	*cpu.MinimumBuild = 40
	*cpu.MinimumTCB.SnpSpl = 23
	*cpu.MinimumLaunchTCB.SnpSpl = 23
	*cpu.MinimumTCB.UcodeSpl = 84
	*cpu.MinimumLaunchTCB.UcodeSpl = 84
	*cpu.MinimumLaunchMitigationVector = 0
	*cpu.MinimumCurrentMitigationVector = 0
	baseline, _ := json.Marshal(baselineManifest)
	if _, err = appraise(input.Envelope, nonce, baseline); err != nil {
		t.Fatalf("real baseline: %v", err)
	}
	if _, err = verify(input.Envelope, nonce); err == nil {
		t.Fatal("accepted underpatched real CPU")
	}
	var original map[string]any
	if err = json.Unmarshal(input.Envelope, &original); err != nil {
		t.Fatal(err)
	}
	// Discard all provider provenance, reference values and freshness witnesses.
	collateral := original["collateral"].([]any)
	kept := make([]any, 0, 2)
	for _, c := range collateral {
		if strings.HasPrefix(c.(map[string]any)["format"].(string), "https://tinfoil.sh/collateral/amd-") {
			kept = append(kept, c)
		}
	}
	if len(kept) != 2 {
		t.Fatal("expected exactly AMD VCEK and CRL collateral")
	}
	original["collateral"] = kept
	stripped, _ := json.Marshal(original)
	if _, err = appraise(stripped, nonce, baseline); err != nil {
		t.Fatalf("provider-authority-free positive: %v", err)
	}
	wrong := append([]byte{}, nonce...)
	wrong[0] ^= 1
	if _, err = appraise(stripped, wrong, baseline); err == nil {
		t.Fatal("accepted replay nonce")
	}
	for _, mutation := range []struct {
		section string
		index   int
	}{{"crypto_material", 0}, {"crypto_material", 1}, {"device_evidence", 0}} {
		section := mutation.section
		var d map[string]any
		json.Unmarshal(stripped, &d)
		decoded, err := base64.StdEncoding.DecodeString(d[section].(string))
		if err != nil {
			t.Fatal(err)
		}
		var items map[string]any
		json.Unmarshal(decoded, &items)
		item := items["items"].([]any)[mutation.index].(map[string]any)
		if section == "crypto_material" {
			item["data"] = strings.Repeat("01", 32)
		} else {
			item["evidence"].(map[string]any)["nonce"] = strings.Repeat("01", 32)
		}
		changed, _ := json.Marshal(items)
		d[section] = base64.StdEncoding.EncodeToString(changed)
		hashes := d["cpu_evidence"].(map[string]any)["endorsed"].(map[string]any)
		// Recompute every untrusted envelope hash/REPORT_DATA field. Only the actual
		// signed CPU report remains unchanged, exercising cryptographic association.
		recomputeEnvelope(t, d, hashes)
		tampered, _ := json.Marshal(d)
		if _, _, err = envelope.Check(tampered, nonce); err != nil {
			t.Fatalf("well-formed mutation: %v", err)
		}
		if _, err = appraise(tampered, nonce, baseline); err == nil {
			t.Fatalf("accepted forged %s CPU binding", section)
		}
	}
	// A valid CPU signature still cannot authorize an unapproved launch digest.
	changedPolicy := bytes.ReplaceAll(baseline, []byte(baselineManifest.Measurement), []byte(strings.Repeat("0", 96)))
	if _, err = appraise(stripped, nonce, changedPolicy); err == nil {
		t.Fatal("accepted wrong workload measurement")
	}
	// A forged signed report must fail authentication, before local policy appraisal.
	var forged map[string]any
	json.Unmarshal(stripped, &forged)
	reportMap := forged["cpu_evidence"].(map[string]any)
	reportBytes, _ := base64.StdEncoding.DecodeString(reportMap["report_base64"].(string))
	reportBytes[672] ^= 1
	reportMap["report_base64"] = base64.StdEncoding.EncodeToString(reportBytes)
	forgedBytes, _ := json.Marshal(forged)
	if _, err = appraise(forgedBytes, nonce, baseline); err == nil || err.Error() != "TEE_CPU_SIGNATURE_REJECTED" {
		t.Fatal("forged CPU signature was not rejected during authentication")
	}
	// Ensure the security floor is not chosen from the incoming reference values.
	p := mustPolicy(t, localPolicyBytes())
	if *p.MinimumTCB.SnpSpl != 27 || *p.MinimumTCB.UcodeSpl != 86 {
		t.Fatal("candidate floor changed")
	}
}

func mustPolicy(t *testing.T, raw []byte) *policy.SEVSNPPolicy {
	t.Helper()
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m.CPU.SEVSNP
}

func TestPolicyCompleteness(t *testing.T) {
	p := mustPolicy(t, localPolicyBytes())
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if *p.MinimumBuild != 49 || *p.MinimumTCB.BlSpl != 10 || *p.MinimumTCB.SnpSpl != 27 || *p.MinimumTCB.UcodeSpl != 86 {
		t.Fatal("manufacturer candidate floor changed")
	}
	if p.GuestPolicy.Debug || p.GuestPolicy.MigrateMA || !p.PlatformInfo.AliasCheckComplete || p.PermitProvisionalFirmware {
		t.Fatal("unsafe candidate CPU settings")
	}
	// Manufacturer mitigation requirements are sets of bits, not numeric ordering.
	if *p.MinimumLaunchMitigationVector != 7 || *p.MinimumCurrentMitigationVector != 7 {
		t.Fatal("missing required mitigation bits")
	}
}

func TestLiveTDXQuote(t *testing.T) {
	path := os.Getenv("PI_TEE_TDX_TEST_EVIDENCE")
	if path == "" {
		t.Skip("set PI_TEE_TDX_TEST_EVIDENCE to a fresh TDX evidence file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	input, nonce, err := decodeInput(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	result, err := verify(input.Envelope, nonce)
	if err != nil {
		t.Fatalf("real TDX local pin: %v", err)
	}
	if !result.CPUVerified || result.GPUVerified || result.IndependentApproval || result.ProviderReferenceAuthority {
		t.Fatal("overclaimed CPU proof")
	}
	var original map[string]any
	json.Unmarshal(input.Envelope, &original)
	kept := []any{}
	for _, c := range original["collateral"].([]any) {
		if c.(map[string]any)["format"] == envelope.CollateralIntelPCSV1Format {
			kept = append(kept, c)
		}
	}
	if len(kept) != 1 {
		t.Fatal("expected Intel PCS collateral")
	}
	original["collateral"] = kept
	stripped, _ := json.Marshal(original)
	if _, err = verify(stripped, nonce); err != nil {
		t.Fatalf("provider-authority-free TDX: %v", err)
	}
	wrong := append([]byte{}, nonce...)
	wrong[0] ^= 1
	if _, err = verify(stripped, wrong); err == nil {
		t.Fatal("accepted replay nonce")
	}
	// A different guest boot profile must not become authorized from reference values.
	wrongBoot := bytes.ReplaceAll(tdxCandidate, []byte(`7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114`), []byte(strings.Repeat("0", 96)))
	if _, err = appraise(stripped, nonce, wrongBoot); err == nil {
		t.Fatal("accepted different MRTD")
	}
	for _, mutation := range []struct {
		section string
		index   int
	}{{"crypto_material", 0}, {"crypto_material", 1}, {"device_evidence", 0}} {
		section := mutation.section
		var d map[string]any
		json.Unmarshal(stripped, &d)
		decoded, _ := base64.StdEncoding.DecodeString(d[section].(string))
		var items map[string]any
		json.Unmarshal(decoded, &items)
		item := items["items"].([]any)[mutation.index].(map[string]any)
		if section == "crypto_material" {
			item["data"] = strings.Repeat("01", 32)
		} else {
			item["evidence"].(map[string]any)["nonce"] = strings.Repeat("01", 32)
		}
		changed, _ := json.Marshal(items)
		d[section] = base64.StdEncoding.EncodeToString(changed)
		recomputeEnvelope(t, d, d["cpu_evidence"].(map[string]any)["endorsed"].(map[string]any))
		tampered, _ := json.Marshal(d)
		if _, _, err = envelope.Check(tampered, nonce); err != nil {
			t.Fatalf("well-formed mutation: %v", err)
		}
		if _, err = verify(tampered, nonce); err == nil {
			t.Fatalf("accepted forged TDX %s binding", section)
		}
	}
}
