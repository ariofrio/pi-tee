package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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
