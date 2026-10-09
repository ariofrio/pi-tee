package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

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

// Compare strict decoded fields with the CPU-accepted statement; independent parsers must not select different boot expectations.
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

// Digest-authenticated deployment bytes must equal that statement predicate, binding runtime/OCI checks to the same CPU workload.
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
	if !productionPolicy(name) {
		return nil, errors.New("TEE_CPU_POLICY_REJECTED")
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

// Local SEV-SNP floors per CPU, keyed on the report's authenticated CPUID
// family/model/stepping. AMD has no UpToDate verdict, so these track AMD's
// bulletins and must be raised as AMD publishes fixes:
//   - AMD-SB-3019 (CVE-2024-56161), AMD-SB-3020 (CVE-2025-0033): SNP SPL
//     0x1B on Genoa/Genoa-X, 0x04 on Turin.
//   - AMD-SB-3027 (CVE-2025-29943): microcode SPL 0x56 Genoa B1, 0x51
//     Genoa-X B2, 0x51 Turin C1.
//
// Bootloader/TEE/FMC floors and the build/API minimums come from Tinfoil's
// SDK before v3 delegated them (tinfoil-go 05e8179 verifier/attestation/sev.go).
type snpFloor struct {
	turin bool
	build int
	api   [2]int
	tcb   policy.TCB
}

var snpFloors = map[[3]byte]snpFloor{
	{0x19, 0x11, 0x01}: {false, 21, [2]int{1, 55}, policy.TCB{BlSpl: u8(7), TeeSpl: u8(0), SnpSpl: u8(0x1b), UcodeSpl: u8(0x56)}},
	{0x19, 0x11, 0x02}: {false, 21, [2]int{1, 55}, policy.TCB{BlSpl: u8(7), TeeSpl: u8(0), SnpSpl: u8(0x1b), UcodeSpl: u8(0x51)}},
	{0x1a, 0x02, 0x01}: {true, 0, [2]int{1, 58}, policy.TCB{FmcSpl: u8(1), BlSpl: u8(1), TeeSpl: u8(1), SnpSpl: u8(0x04), UcodeSpl: u8(0x51)}},
}

func u8(value uint8) *uint8 { return &value }

func raiseTCB(tcb *policy.TCB, floor policy.TCB) {
	for _, pair := range [][2]*uint8{{tcb.FmcSpl, floor.FmcSpl}, {tcb.BlSpl, floor.BlSpl}, {tcb.TeeSpl, floor.TeeSpl}, {tcb.SnpSpl, floor.SnpSpl}, {tcb.UcodeSpl, floor.UcodeSpl}} {
		if pair[0] != nil && pair[1] != nil {
			*pair[0] = max(*pair[0], *pair[1])
		}
	}
}

func versionParts(version string) ([2]int, bool) {
	major, minor, ok := strings.Cut(version, ".")
	a, errA := strconv.Atoi(major)
	b, errB := strconv.Atoi(minor)
	return [2]int{a, b}, ok && errA == nil && errB == nil
}

// Platform publishers also sign development policies; only production ones
// may serve inference.
func productionPolicy(name string) bool { return strings.HasSuffix(name, "-prod") }

// snpCPU reads CPUID family/model/stepping (report version 3+, offsets
// 0x188-0x18A) from the report bytes quote.Authenticate verified.
func snpCPU(reportBase64 string) ([3]byte, error) {
	report, err := base64.StdEncoding.DecodeString(reportBase64)
	if err != nil || len(report) != 0x4a0 || binary.LittleEndian.Uint32(report[0:4]) < 3 {
		return [3]byte{}, errors.New("TEE_CPU_POLICY_REJECTED")
	}
	return [3]byte{report[0x188], report[0x189], report[0x18a]}, nil
}

// SEV-SNP: the publisher's floors, raised to the local per-CPU floors, and
// AMD's document-carried CRL govern firmware. Independently require a
// production policy for a non-debug, non-migratable guest at VMPL0 on
// released firmware.
func floorSNPArtifact(artifact *policy.Artifact, identity string, cpu [3]byte) (*policy.Artifact, error) {
	return snpArtifactPolicy(artifact, identity, cpu, true)
}

func baseSNPArtifact(artifact *policy.Artifact, identity string, cpu [3]byte) (*policy.Artifact, error) {
	return snpArtifactPolicy(artifact, identity, cpu, false)
}

func snpArtifactPolicy(artifact *policy.Artifact, identity string, cpu [3]byte, floors bool) (*policy.Artifact, error) {
	reject := errors.New("TEE_CPU_POLICY_REJECTED")
	floor, known := snpFloors[cpu]
	if !known {
		return nil, reject
	}
	raw, err := json.Marshal(artifact)
	if err != nil {
		return nil, err
	}
	copy, err := policy.Parse(raw)
	if err != nil {
		return nil, err
	}
	name, selected, err := copy.PolicyFor(identity, policy.PlatformSEVSNP)
	if err != nil {
		return nil, err
	}
	snp := selected.SEVSNP
	if !productionPolicy(name) || snp == nil || snp.GuestPolicy.Debug || snp.GuestPolicy.MigrateMA || snp.PermitProvisionalFirmware || snp.VMPL == nil || *snp.VMPL != 0 ||
		snp.MinimumBuild == nil || (snp.MinimumTCB.FmcSpl != nil) != floor.turin || (snp.MinimumLaunchTCB.FmcSpl != nil) != floor.turin {
		return nil, reject
	}
	version, ok := versionParts(snp.MinimumAPIVersion)
	if !ok {
		return nil, reject
	}
	if !floors {
		return copy, nil
	}
	if version[0] < floor.api[0] || (version[0] == floor.api[0] && version[1] < floor.api[1]) {
		snp.MinimumAPIVersion = fmt.Sprintf("%d.%d", floor.api[0], floor.api[1])
	}
	*snp.MinimumBuild = max(*snp.MinimumBuild, uint8(floor.build))
	raiseTCB(&snp.MinimumTCB, floor.tcb)
	raiseTCB(&snp.MinimumLaunchTCB, floor.tcb)
	copy.Policies[name] = *selected
	return copy, nil
}
