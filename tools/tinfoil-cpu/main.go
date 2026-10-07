// Offline candidate appraisal. This command cannot enable Approved inference.
package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
)

const maxInputBytes = 2 * 1024 * 1024

//go:embed candidate.json
var candidate []byte

//go:embed tdx.json
var tdxCandidate []byte

func localPolicyBytes() []byte { return append([]byte{}, candidate...) }

type input struct {
	Nonce    string          `json:"nonce"`
	Envelope json.RawMessage `json:"envelope"`
}
type manifest struct {
	Qualification        string                                `json:"qualification"`
	CPUID                uint32                                `json:"cpuid"`
	Measurement          string                                `json:"measurement,omitempty"`
	Registers            []string                              `json:"registers,omitempty"`
	PlatformMeasurements map[string]policy.PlatformMeasurement `json:"platform_measurements,omitempty"`
	CPU                  policy.Policy                         `json:"cpu"`
	Shape                policy.Shape                          `json:"shape"`
}
type result struct {
	CPUVerified                bool   `json:"cpuVerified"`
	GPUVerified                bool   `json:"gpuVerified"`
	IndependentApproval        bool   `json:"independentApproval"`
	ProviderReferenceAuthority bool   `json:"runtimeProviderReferenceAuthority"`
	PolicySHA256               string `json:"policySha256"`
}

func decodeInput(reader io.Reader) (input, []byte, error) {
	var i input
	b, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	if err != nil || len(b) > maxInputBytes {
		return i, nil, errors.New("TEE_EVIDENCE_INPUT_REJECTED")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&i); err != nil {
		return i, nil, errors.New("TEE_EVIDENCE_INPUT_REJECTED")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return i, nil, errors.New("TEE_EVIDENCE_INPUT_REJECTED")
	}
	nonce, err := hex.DecodeString(i.Nonce)
	if err != nil || len(nonce) != envelope.NonceSize || i.Nonce != hex.EncodeToString(nonce) || len(i.Envelope) == 0 {
		return i, nil, errors.New("TEE_EVIDENCE_INPUT_REJECTED")
	}
	return i, nonce, nil
}
func verify(raw []byte, nonce []byte) (*result, error) {
	if len(raw) > maxInputBytes {
		return nil, errors.New("TEE_EVIDENCE_INPUT_REJECTED")
	}
	doc, err := envelope.Parse(raw)
	if err != nil {
		return nil, errors.New("TEE_ENVELOPE_REJECTED")
	}
	switch doc.CPUEvidence.Format {
	case envelope.SEVSNPReportV1Format:
		return appraise(raw, nonce, localPolicyBytes())
	case envelope.TDXQuoteV1Format:
		return appraise(raw, nonce, tdxCandidate)
	default:
		return nil, errors.New("TEE_CPU_PLATFORM_REJECTED")
	}
}

func appraise(raw []byte, nonce []byte, local []byte) (*result, error) {
	if len(raw) > maxInputBytes {
		return nil, errors.New("TEE_EVIDENCE_INPUT_REJECTED")
	}
	doc, reportData, err := envelope.Check(raw, nonce)
	if err != nil {
		return nil, errors.New("TEE_ENVELOPE_REJECTED")
	}
	if doc.CPUEvidence.Format != envelope.SEVSNPReportV1Format && doc.CPUEvidence.Format != envelope.TDXQuoteV1Format {
		return nil, errors.New("TEE_CPU_PLATFORM_REJECTED")
	}
	authenticated, err := quote.Authenticate(doc)
	if err != nil {
		return nil, errors.New("TEE_CPU_SIGNATURE_REJECTED")
	}
	var m manifest
	d := json.NewDecoder(bytes.NewReader(local))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || m.Qualification != "candidate-only" || m.CPU.Platform != authenticated.Platform {
		return nil, errors.New("TEE_LOCAL_POLICY_REJECTED")
	}
	if authenticated.Platform == policy.PlatformSEVSNP {
		rawReport, err := base64.StdEncoding.DecodeString(doc.CPUEvidence.ReportBase64)
		if err != nil {
			return nil, errors.New("TEE_CPU_SIGNATURE_REJECTED")
		}
		report, err := abi.ReportToProto(rawReport)
		if err != nil {
			return nil, errors.New("TEE_CPU_SIGNATURE_REJECTED")
		}
		if report.GetCpuid1EaxFms() != m.CPUID {
			return nil, errors.New("TEE_CPU_PLATFORM_REJECTED")
		}
	}
	// Any manufacturer-authenticated machine of the permitted product/configuration
	// may be considered. Identity from authenticated bytes is only a lookup key;
	// the locally embedded workload and security values decide authorization.
	artifactBytes, err := json.Marshal(policy.Artifact{Format: policy.ArtifactFormat, Measurements: m.PlatformMeasurements, Machines: map[string]string{authenticated.Identity: "local-candidate"}, Policies: map[string]policy.Policy{"local-candidate": m.CPU}})
	if err != nil {
		return nil, errors.New("TEE_LOCAL_POLICY_REJECTED")
	}
	artifact, err := policy.Parse(artifactBytes)
	if err != nil {
		return nil, errors.New("TEE_LOCAL_POLICY_REJECTED")
	}
	code := &measurement.Measurement{Type: measurement.SevGuestV2, Registers: []string{m.Measurement}}
	if authenticated.Platform == policy.PlatformTDX {
		code = &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: m.Registers}
	}
	assembled, err := quote.Assemble(artifact, code, &m.Shape, reportData, authenticated)
	if err != nil {
		return nil, errors.New("TEE_LOCAL_POLICY_REJECTED")
	}
	if assembled.Validate() != nil {
		return nil, errors.New("TEE_CPU_POLICY_REJECTED")
	}
	// Deliberately do not return inference keys or an Approved decision: this only
	// establishes the CPU-side candidate, not GPU/channel/runtime qualification.
	digest := sha256.Sum256(local)
	return &result{CPUVerified: true, PolicySHA256: hex.EncodeToString(digest[:])}, nil
}
func main() {
	i, nonce, err := decodeInput(os.Stdin)
	var verified *result
	if err == nil {
		verified, err = verify(i.Envelope, nonce)
	}
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"cpuVerified": false, "independentApproval": false, "failure": err.Error()})
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(verified)
}
