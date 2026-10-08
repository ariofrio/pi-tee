package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

func TestPolicyInspectionAppliesFloorsWithoutAlteringPublisherInput(t *testing.T) {
	for _, minimum := range []struct {
		svn         string
		edition     int
		wantSVN     string
		wantEdition int
	}{
		{strings.Repeat("00", 16), 0, "030102" + strings.Repeat("00", 13), 20},
		{"040203" + strings.Repeat("00", 13), 25, "040203" + strings.Repeat("00", 13), 25},
	} {
		input, _ := json.Marshal(map[string]any{
			"identity": strings.Repeat("a", 32),
			"artifact": map[string]any{
				"format":       "https://tinfoil.sh/predicate/platform-endorsements/v1",
				"machines":     map[string]string{strings.Repeat("a", 32): "test"},
				"measurements": map[string]any{"test": map[string]any{"mrtd": strings.Repeat("0", 96), "rtmr0": strings.Repeat("0", 96), "shape": map[string]any{"cpus": 16, "memory_mb": 65536, "gpus": 1, "disks": 5}}},
				"policies": map[string]any{"test": map[string]any{"platform": "tdx", "tdx": map[string]any{
					"qe_vendor_id": "939a7233f79c4ca9940a0db3957f0607", "minimum_tee_tcb_svn": minimum.svn,
					"mr_seam": strings.Repeat("0", 96), "td_attributes": "0000001000000000", "xfam": strings.Repeat("0", 16),
					"minimum_tcb_evaluation_data_number": minimum.edition, "platform_measurements": []string{"test"},
				}}},
			},
		})
		var out bytes.Buffer
		if runPolicyInspection(bytes.NewReader(input), &out) != 0 {
			t.Fatalf("policy inspection: %s", out.String())
		}
		var result map[string]any
		if json.Unmarshal(out.Bytes(), &result) != nil || result["minimumTEETCBSVN"] != minimum.wantSVN || result["minimumTCBEvaluationDataNumber"] != float64(minimum.wantEdition) || result["publisherInputUnchanged"] != true || result["policyAuthenticated"] != false || result["inferenceQualified"] != false {
			t.Fatalf("incorrect local floor application/scope: %s", out.String())
		}
	}
}

func snpArtifact(t *testing.T, turin bool, weak bool) (*policy.Artifact, string) {
	t.Helper()
	tcb := map[string]any{"bl_spl": 7, "tee_spl": 0, "snp_spl": 14, "ucode_spl": 72}
	api, build := "1.55", 21
	info := map[string]any{"smt_enabled": true, "tsme_enabled": true, "ecc_enabled": true, "alias_check_complete": true}
	if turin {
		tcb = map[string]any{"fmc_spl": 1, "bl_spl": 1, "tee_spl": 1, "snp_spl": 4, "ucode_spl": 82}
		api, build = "1.58", 0
		info["iommu_write_safe"] = true
	}
	if weak {
		for key := range tcb {
			tcb[key] = 0
		}
		api, build = "0.0", 0
	}
	identity := strings.Repeat("b", 128)
	raw, _ := json.Marshal(map[string]any{
		"format":   "https://tinfoil.sh/predicate/platform-endorsements/v1",
		"machines": map[string]string{identity: "test"},
		"policies": map[string]any{"test": map[string]any{"platform": "sev-snp", "sev_snp": map[string]any{
			"minimum_build": build, "minimum_api_version": api, "minimum_abi_version": "0.0", "minimum_guest_svn": 0,
			"minimum_tcb": tcb, "minimum_launch_tcb": tcb,
			"guest_policy":  map[string]any{"debug": false, "smt": true, "migrate_ma": false, "single_socket": false},
			"platform_info": info, "permit_provisional_firmware": false, "vmpl": 0,
			"host_data": strings.Repeat("0", 64), "image_id": strings.Repeat("0", 32), "family_id": strings.Repeat("0", 32),
			"minimum_launch_mitigation_vector": 0, "minimum_current_mitigation_vector": 0,
		}}},
	})
	artifact, err := policy.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return artifact, identity
}

// AMD has no UpToDate verdict: local floors backstop the publisher's, as for TDX.
func TestSNPLocalFloorsRaiseWeakPublisherPolicy(t *testing.T) {
	for _, turin := range []bool{false, true} {
		reference, identity := snpArtifact(t, turin, false)
		_, want, _ := reference.PolicyFor(identity, policy.PlatformSEVSNP)
		weak, _ := snpArtifact(t, turin, true)
		floored, err := floorSNPArtifact(weak, identity)
		if err != nil {
			t.Fatal(err)
		}
		_, got, _ := floored.PolicyFor(identity, policy.PlatformSEVSNP)
		if !reflect.DeepEqual(got.SEVSNP.MinimumTCB, want.SEVSNP.MinimumTCB) || !reflect.DeepEqual(got.SEVSNP.MinimumLaunchTCB, want.SEVSNP.MinimumLaunchTCB) ||
			*got.SEVSNP.MinimumBuild != *want.SEVSNP.MinimumBuild || got.SEVSNP.MinimumAPIVersion != want.SEVSNP.MinimumAPIVersion {
			t.Fatalf("turin=%v: floors not applied: %+v", turin, got.SEVSNP)
		}
		_, original, _ := weak.PolicyFor(identity, policy.PlatformSEVSNP)
		if *original.SEVSNP.MinimumTCB.UcodeSpl != 0 {
			t.Fatal("publisher input was altered")
		}
		// Stronger publisher floors are preserved.
		strong, _ := snpArtifact(t, turin, false)
		_, selected, _ := strong.PolicyFor(identity, policy.PlatformSEVSNP)
		*selected.SEVSNP.MinimumTCB.UcodeSpl = 250
		selected.SEVSNP.MinimumAPIVersion = "9.12"
		name, _, _ := strong.PolicyFor(identity, policy.PlatformSEVSNP)
		strong.Policies[name] = *selected
		floored, err = floorSNPArtifact(strong, identity)
		_, got, _ = floored.PolicyFor(identity, policy.PlatformSEVSNP)
		if err != nil || *got.SEVSNP.MinimumTCB.UcodeSpl != 250 || got.SEVSNP.MinimumAPIVersion != "9.12" {
			t.Fatalf("turin=%v: stronger floors not preserved: %v %+v", turin, err, got.SEVSNP)
		}
	}
}
