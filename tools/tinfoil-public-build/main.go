// This evidence-only command authenticates public release measurements. It does
// not qualify GPU protection, key custody, runtime behavior, or inference.
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
)

const (
	maxInputBytes = 2 * 1024 * 1024
	codeRepo      = "tinfoilsh/confidential-gemma4-31b"
	codeWorkflow  = "tinfoil-release-publish.yml"
	platformRepo  = "tinfoilsh/platform-endorsements"
)

var stableTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type input struct {
	Nonce    string          `json:"nonce"`
	Envelope json.RawMessage `json:"envelope"`
}

type result struct {
	CPUVerified         bool      `json:"cpuVerified"`
	PublicBuildVerified bool      `json:"publicBuildVerified"`
	GPUVerified         bool      `json:"gpuVerified"`
	InferenceQualified  bool      `json:"inferenceQualified"`
	Repo                string    `json:"repo"`
	Workflow            string    `json:"workflow"`
	Tag                 string    `json:"tag"`
	Commit              string    `json:"commit"`
	Digest              string    `json:"digest"`
	PlatformTag         string    `json:"platformTag"`
	PlatformCommit      string    `json:"platformCommit"`
	PlatformDigest      string    `json:"platformDigest"`
	CodeFreshness       time.Time `json:"codeFreshness"`
	PlatformFreshness   time.Time `json:"platformFreshness"`
}

// The SDK accepts any tagged workflow in the code repository. Narrow it to the
// one release workflow explicitly trusted here, without freezing its commits.
func requireCodeWorkflow(raw []byte, tag string) error {
	if !stableTag.MatchString(tag) {
		return errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
	}
	cert, err := x509.ParseCertificate(b.GetVerificationMaterial().GetCertificate().GetRawBytes())
	if err != nil {
		return errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
	}
	expected := "https://github.com/" + codeRepo + "/.github/workflows/" + codeWorkflow + "@refs/tags/" + tag
	if len(cert.URIs) != 1 || cert.URIs[0].String() != expected {
		return errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
	}
	extensions, err := certificate.ParseExtensions(cert.Extensions)
	if err != nil || extensions.SourceRepositoryURI != "https://github.com/"+codeRepo ||
		extensions.SourceRepositoryRef != "refs/tags/"+tag || extensions.BuildSignerURI != expected ||
		extensions.SourceRepositoryVisibilityAtSigning != "public" ||
		extensions.BuildSignerDigest != extensions.SourceRepositoryDigest {
		return errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
	}
	return nil
}

func verify(raw, nonce []byte, now time.Time) (*result, error) {
	doc, reportData, err := envelope.Check(raw, nonce)
	if err != nil {
		return nil, errors.New("TEE_ENVELOPE_REJECTED")
	}
	if doc.CPUEvidence.Format != envelope.TDXQuoteV1Format {
		return nil, errors.New("TEE_CPU_PLATFORM_REJECTED")
	}
	ref, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstoreCodeV1Format)
	if err != nil || ref.Repo != codeRepo {
		return nil, errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
	}
	if err = requireCodeWorkflow(ref.SigstoreBundle, ref.Tag); err != nil {
		return nil, err
	}
	code, err := provenance.AuthenticateCode(ref.SigstoreBundle, codeRepo, ref.Tag, ref.Digest)
	if err != nil {
		return nil, errors.New("TEE_PUBLIC_BUILD_SIGNATURE_REJECTED")
	}
	fresh, err := doc.FreshnessCollateral(envelope.FreshnessCollateralIDCode)
	if err != nil {
		return nil, errors.New("TEE_PUBLIC_BUILD_FRESHNESS_REJECTED")
	}
	codeTime, err := provenance.AuthenticateFreshness(fresh.SigstoreBundle, &code.AuthenticatedArtifact, now)
	if err != nil {
		return nil, errors.New("TEE_PUBLIC_BUILD_FRESHNESS_REJECTED")
	}
	platformRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstorePlatformV1Format)
	if err != nil || platformRef.Repo != platformRepo || !stableTag.MatchString(platformRef.Tag) {
		return nil, errors.New("TEE_PLATFORM_REFERENCE_REJECTED")
	}
	platform, err := provenance.AuthenticatePlatformEndorsements(platformRef.SigstoreBundle, platformRepo, platformRef.Tag, platformRef.Digest)
	if err != nil {
		return nil, errors.New("TEE_PLATFORM_REFERENCE_REJECTED")
	}
	platformFresh, err := doc.FreshnessCollateral(envelope.FreshnessCollateralIDPlatform)
	if err != nil {
		return nil, errors.New("TEE_PLATFORM_FRESHNESS_REJECTED")
	}
	platformTime, err := provenance.AuthenticateFreshness(platformFresh.SigstoreBundle, &platform.AuthenticatedArtifact, now)
	if err != nil {
		return nil, errors.New("TEE_PLATFORM_FRESHNESS_REJECTED")
	}
	authenticated, err := quote.Authenticate(doc)
	if err != nil {
		return nil, errors.New("TEE_CPU_SIGNATURE_REJECTED")
	}
	_, cpu, err := platform.Artifact.PolicyFor(authenticated.Identity, policy.PlatformTDX)
	if err != nil {
		return nil, errors.New("TEE_CPU_POLICY_REJECTED")
	}
	// Apply local floors in addition to authenticated publisher policy. Workload
	// registers and firmware references remain dynamic.
	minimum, err := hex.DecodeString(cpu.TDX.MinimumTEETCBSVN)
	if err != nil || len(minimum) != 16 || cpu.TDX.TDAttributes != "0000001000000000" ||
		cpu.TDX.QEVendorID != "939a7233f79c4ca9940a0db3957f0607" {
		return nil, errors.New("TEE_CPU_POLICY_REJECTED")
	}
	for index, floor := range []byte{3, 1, 2} {
		minimum[index] = max(minimum[index], floor)
	}
	cpu.TDX.MinimumTEETCBSVN = hex.EncodeToString(minimum)
	*cpu.TDX.MinimumTCBEvaluationDataNumber = max(*cpu.TDX.MinimumTCBEvaluationDataNumber, 20)
	assembled, err := quote.Assemble(platform.Artifact, code.Measurement, code.Shape, reportData, authenticated)
	if err != nil || assembled.Validate() != nil {
		return nil, errors.New("TEE_CPU_POLICY_REJECTED")
	}
	return &result{CPUVerified: true, PublicBuildVerified: true, Repo: codeRepo, Workflow: codeWorkflow,
		Tag: code.Tag, Commit: code.Commit, Digest: code.Digest,
		PlatformTag: platform.Tag, PlatformCommit: platform.Commit, PlatformDigest: platform.Digest,
		CodeFreshness: codeTime, PlatformFreshness: platformTime}, nil
}

func run(reader io.Reader, writer io.Writer, now time.Time) int {
	raw, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	var i input
	if err == nil && len(raw) <= maxInputBytes {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		err = d.Decode(&i)
		var extra any
		if err == nil && d.Decode(&extra) != io.EOF {
			err = errors.New("TEE_EVIDENCE_INPUT_REJECTED")
		}
	} else {
		err = errors.New("TEE_EVIDENCE_INPUT_REJECTED")
	}
	nonce, nonceErr := hex.DecodeString(i.Nonce)
	if err == nil && (nonceErr != nil || len(nonce) != envelope.NonceSize || i.Nonce != hex.EncodeToString(nonce)) {
		err = errors.New("TEE_EVIDENCE_INPUT_REJECTED")
	}
	var checked *result
	if err == nil {
		checked, err = verify(i.Envelope, nonce, now)
	}
	if err != nil {
		code := "TEE_EVIDENCE_INPUT_REJECTED"
		if len(err.Error()) > 4 && err.Error()[:4] == "TEE_" {
			code = err.Error()
		}
		json.NewEncoder(writer).Encode(map[string]any{"cpuVerified": false, "publicBuildVerified": false, "inferenceQualified": false, "failure": code})
		return 1
	}
	if json.NewEncoder(writer).Encode(checked) != nil {
		return 1
	}
	return 0
}

func main() {
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	os.Exit(run(os.Stdin, os.Stdout, time.Now()))
}
