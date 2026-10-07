package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// A public inspection seam for the exact floor application used by quote
// assembly. Unsigned input/output cannot authorize hardware or inference.
func runPolicyInspection(reader io.Reader, writer io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	var input struct {
		Artifact json.RawMessage `json:"artifact"`
		Identity string          `json:"identity"`
	}
	var result map[string]any
	if err == nil && len(raw) <= maxInputBytes && decodeOne(raw, &input) == nil {
		artifact, parseErr := policy.Parse(input.Artifact)
		if parseErr == nil {
			before, _ := json.Marshal(artifact)
			floored, floorErr := floorTDXArtifact(artifact, input.Identity)
			after, _ := json.Marshal(artifact)
			if floorErr == nil && bytes.Equal(before, after) {
				_, selected, selectErr := floored.PolicyFor(input.Identity, policy.PlatformTDX)
				if selectErr == nil {
					result = map[string]any{"policyAuthenticated": false, "inferenceQualified": false, "publisherInputUnchanged": true,
						"minimumTEETCBSVN": selected.TDX.MinimumTEETCBSVN, "minimumTCBEvaluationDataNumber": *selected.TDX.MinimumTCBEvaluationDataNumber}
				} else {
					err = selectErr
				}
			} else {
				err = errors.New("policy floor application")
			}
		} else {
			err = parseErr
		}
	}
	if err != nil || result == nil {
		json.NewEncoder(writer).Encode(map[string]any{"policyAuthenticated": false, "inferenceQualified": false, "failure": "TEE_CPU_POLICY_REJECTED"})
		return 1
	}
	if json.NewEncoder(writer).Encode(result) != nil {
		return 1
	}
	return 0
}
