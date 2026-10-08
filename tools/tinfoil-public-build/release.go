package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

type deployment struct {
	SNP string `json:"snp_measurement"`
	TDX struct {
		RTMR1 string `json:"rtmr1"`
		RTMR2 string `json:"rtmr2"`
	} `json:"tdx_measurement"`
	Shape struct {
		CPUs     int `json:"cpus"`
		MemoryMB int `json:"memory_mb"`
		GPUs     int `json:"gpus"`
		Disks    int `json:"disks"`
	} `json:"vm_shape"`
	Command string      `json:"cmdline"`
	Hashes  cvmManifest `json:"hashes"`
	Config  string      `json:"config"`
}

func codePredicate(raw []byte, code *provenance.Code) (*deployment, string, error) {
	reject := errors.New("TEE_PUBLIC_BUILD_BINDING_REJECTED")
	var b bundle.Bundle
	if b.UnmarshalJSON(raw) != nil {
		return nil, "", reject
	}
	payload := b.GetDsseEnvelope().GetPayload()
	var statement struct {
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
		Subject       json.RawMessage `json:"subject"`
		Predicate     deployment      `json:"predicate"`
	}
	if decodeOne(payload, &statement) != nil || statement.Type != "https://in-toto.io/Statement/v1" ||
		statement.PredicateType != string(measurement.SnpTdxMultiPlatformV1) {
		return nil, "", reject
	}
	p := &statement.Predicate
	if code.Measurement == nil || len(code.Measurement.Registers) != 3 || code.Shape == nil || code.Shape.GPUs == nil ||
		!reflect.DeepEqual(code.Measurement.Registers, []string{p.SNP, p.TDX.RTMR1, p.TDX.RTMR2}) ||
		code.Shape.CPUs != p.Shape.CPUs || code.Shape.MemoryMB != p.Shape.MemoryMB || *code.Shape.GPUs != p.Shape.GPUs || code.Shape.Disks != p.Shape.Disks {
		return nil, "", reject
	}
	return p, digest256(payload), nil
}

func authenticateDeployment(repo, tag string, raw, releaseBundle []byte) (*provenance.Code, *deployment, string, error) {
	reject := errors.New("TEE_PUBLIC_BUILD_BINDING_REJECTED")
	if requireCodeWorkflow(releaseBundle, repo, tag) != nil {
		return nil, nil, "", reject
	}
	code, err := provenance.AuthenticateCode(releaseBundle, repo, tag, digest256(raw))
	if err != nil {
		return nil, nil, "", reject
	}
	predicate, statementDigest, err := codePredicate(releaseBundle, code)
	var subject deployment
	if err != nil || decodeOne(raw, &subject) != nil || !reflect.DeepEqual(&subject, predicate) {
		return nil, nil, "", reject
	}
	return code, &subject, statementDigest, nil
}

// Own the floored policy copy; never rely on PolicyFor returning shared pointers.
func floorTDXArtifact(artifact *policy.Artifact, identity string) (*policy.Artifact, error) {
	raw, err := json.Marshal(artifact)
	if err != nil {
		return nil, err
	}
	copy, err := policy.Parse(raw)
	if err != nil {
		return nil, err
	}
	name, selected, err := copy.PolicyFor(identity, policy.PlatformTDX)
	if err != nil {
		return nil, err
	}
	minimum, err := policy.DecodeHex("minimum", selected.TDX.MinimumTEETCBSVN, 16)
	if err != nil || selected.TDX.TDAttributes != "0000001000000000" || selected.TDX.QEVendorID != "939a7233f79c4ca9940a0db3957f0607" {
		return nil, errors.New("TEE_CPU_POLICY_REJECTED")
	}
	for index, floor := range []byte{3, 1, 2} {
		minimum[index] = max(minimum[index], floor)
	}
	selected.TDX.MinimumTEETCBSVN = hex.EncodeToString(minimum)
	*selected.TDX.MinimumTCBEvaluationDataNumber = max(*selected.TDX.MinimumTCBEvaluationDataNumber, 20)
	copy.Policies[name] = *selected
	return copy, nil
}

// SEV-SNP has no manufacturer "UpToDate" verdict; the publisher's TCB floors
// and AMD's document-carried CRL govern firmware. Independently require a
// non-debug, non-migratable guest at VMPL0 on released firmware.
func floorSNPArtifact(artifact *policy.Artifact, identity string) (*policy.Artifact, error) {
	raw, err := json.Marshal(artifact)
	if err != nil {
		return nil, err
	}
	copy, err := policy.Parse(raw)
	if err != nil {
		return nil, err
	}
	_, selected, err := copy.PolicyFor(identity, policy.PlatformSEVSNP)
	if err != nil {
		return nil, err
	}
	snp := selected.SEVSNP
	if snp == nil || snp.GuestPolicy.Debug || snp.GuestPolicy.MigrateMA || snp.PermitProvisionalFirmware || snp.VMPL == nil || *snp.VMPL != 0 {
		return nil, errors.New("TEE_CPU_POLICY_REJECTED")
	}
	return copy, nil
}
