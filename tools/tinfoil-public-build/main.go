// This evidence-only command authenticates public release measurements. It does
// not qualify GPU protection, key custody, runtime behavior, or inference.
package main

import (
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
	codeWorkflow  = "tinfoil-release-publish.yml"
	platformRepo  = "tinfoilsh/platform-endorsements"
)

// Workload publishers admitted under the runtime profile, with the model name
// each must serve. Each is trusted only through its tagged release workflow;
// another repository is rejected.
var publicRepos = map[string]string{
	"tinfoilsh/confidential-gemma4-31b":          "gemma4-31b",
	"tinfoilsh/confidential-deepseek-v4-1-flash": "deepseek-v4-1-flash",
	"tinfoilsh/confidential-glm5-3-nvfp4":        "glm-5-3",
}

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
	Platform            string    `json:"platform"`
	Workflow            string    `json:"workflow"`
	Tag                 string    `json:"tag"`
	Commit              string    `json:"commit"`
	Digest              string    `json:"digest"`
	PlatformTag         string    `json:"platformTag"`
	PlatformCommit      string    `json:"platformCommit"`
	PlatformDigest      string    `json:"platformDigest"`
	CodeFreshness       time.Time `json:"codeFreshness"`
	PlatformFreshness   time.Time `json:"platformFreshness"`
	CodeStatementDigest string    `json:"codeStatementDigest"`
	RTMR1               string    `json:"rtmr1"`
	RTMR2               string    `json:"rtmr2"`
	Shape               any       `json:"vmShape"`
}

// The SDK accepts any tagged workflow in the code repository. Narrow it to the
// one release workflow explicitly trusted here, without freezing its commits.
func requireCodeWorkflow(raw []byte, repo, tag string) error {
	if publicRepos[repo] == "" || !stableTag.MatchString(tag) {
		return errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
	}
	return requirePublicWorkflow(raw, repo, codeWorkflow, "refs/tags/"+tag)
}

func requirePublicWorkflow(raw []byte, repo, workflow, ref string) error {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
	}
	cert, err := x509.ParseCertificate(b.GetVerificationMaterial().GetCertificate().GetRawBytes())
	if err != nil {
		return errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
	}
	expected := "https://github.com/" + repo + "/.github/workflows/" + workflow + "@" + ref
	if len(cert.URIs) != 1 || cert.URIs[0].String() != expected {
		return errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
	}
	extensions, err := certificate.ParseExtensions(cert.Extensions)
	if err != nil || extensions.SourceRepositoryURI != "https://github.com/"+repo ||
		extensions.SourceRepositoryRef != ref || extensions.BuildSignerURI != expected ||
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
	if doc.CPUEvidence.Format != envelope.TDXQuoteV1Format && doc.CPUEvidence.Format != envelope.SEVSNPReportV1Format {
		return nil, errors.New("TEE_CPU_PLATFORM_REJECTED")
	}
	// A single conventional code entry is shared with the Node artifact chain.
	var references int
	for _, entry := range doc.Collateral {
		if entry.Format == envelope.CollateralSigstoreCodeV1Format {
			references++
			if entry.ID != "code" || entry.Role != envelope.RoleReferenceValues {
				return nil, errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
			}
		}
	}
	if references != 1 {
		return nil, errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
	}
	ref, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstoreCodeV1Format)
	if err != nil || publicRepos[ref.Repo] == "" {
		return nil, errors.New("TEE_PUBLIC_BUILD_IDENTITY_REJECTED")
	}
	codeRepo := ref.Repo
	if err = requireCodeWorkflow(ref.SigstoreBundle, codeRepo, ref.Tag); err != nil {
		return nil, err
	}
	code, err := provenance.AuthenticateCode(ref.SigstoreBundle, codeRepo, ref.Tag, ref.Digest)
	if err != nil {
		return nil, errors.New("TEE_PUBLIC_BUILD_SIGNATURE_REJECTED")
	}
	predicate, statementDigest, err := codePredicate(ref.SigstoreBundle, code)
	if err != nil {
		return nil, err
	}
	fresh, err := doc.FreshnessCollateral(envelope.FreshnessCollateralIDCode)
	if err != nil || requirePublicWorkflow(fresh.SigstoreBundle, "tinfoilsh/freshness-witness", "freshness.yml", "refs/heads/main") != nil {
		return nil, errors.New("TEE_PUBLIC_BUILD_FRESHNESS_REJECTED")
	}
	codeTime, err := provenance.AuthenticateFreshness(fresh.SigstoreBundle, &code.AuthenticatedArtifact, now)
	if err != nil {
		return nil, errors.New("TEE_PUBLIC_BUILD_FRESHNESS_REJECTED")
	}
	platformRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstorePlatformV1Format)
	if err != nil || platformRef.Repo != platformRepo || !stableTag.MatchString(platformRef.Tag) || requirePublicWorkflow(platformRef.SigstoreBundle, platformRepo, "build.yml", "refs/tags/"+platformRef.Tag) != nil {
		return nil, errors.New("TEE_PLATFORM_REFERENCE_REJECTED")
	}
	platform, err := provenance.AuthenticatePlatformEndorsements(platformRef.SigstoreBundle, platformRepo, platformRef.Tag, platformRef.Digest)
	if err != nil {
		return nil, errors.New("TEE_PLATFORM_REFERENCE_REJECTED")
	}
	platformFresh, err := doc.FreshnessCollateral(envelope.FreshnessCollateralIDPlatform)
	if err != nil || requirePublicWorkflow(platformFresh.SigstoreBundle, "tinfoilsh/freshness-witness", "freshness.yml", "refs/heads/main") != nil {
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
	var floored *policy.Artifact
	switch authenticated.Platform {
	case policy.PlatformTDX:
		floored, err = floorTDXArtifact(platform.Artifact, authenticated.Identity)
	case policy.PlatformSEVSNP:
		floored, err = floorSNPArtifact(platform.Artifact, authenticated.Identity)
	default:
		err = errors.New("TEE_CPU_PLATFORM_REJECTED")
	}
	if err != nil {
		return nil, errors.New("TEE_CPU_POLICY_REJECTED")
	}
	assembled, err := quote.Assemble(floored, code.Measurement, code.Shape, reportData, authenticated)
	if err != nil || assembled.Validate() != nil {
		return nil, errors.New("TEE_CPU_POLICY_REJECTED")
	}
	return &result{CPUVerified: true, PublicBuildVerified: true, Repo: codeRepo, Platform: authenticated.Platform, Workflow: codeWorkflow,
		Tag: code.Tag, Commit: code.Commit, Digest: code.Digest,
		PlatformTag: platform.Tag, PlatformCommit: platform.Commit, PlatformDigest: platform.Digest,
		CodeStatementDigest: statementDigest, RTMR1: predicate.TDX.RTMR1, RTMR2: predicate.TDX.RTMR2, Shape: predicate.Shape,
		CodeFreshness: codeTime, PlatformFreshness: platformTime}, nil
}

func run(reader io.Reader, writer io.Writer, now time.Time) int {
	raw, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	var i input
	if err == nil && len(raw) <= maxInputBytes {
		err = decodeOne(raw, &i)
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
	if len(os.Args) == 2 && os.Args[1] == "--inspect-tdx-policy" {
		os.Exit(runPolicyInspection(os.Stdin, os.Stdout))
	}
	if len(os.Args) == 2 && os.Args[1] == "--runtime-config" {
		os.Exit(runRuntimeRelease(os.Stdin, os.Stdout))
	}
	if len(os.Args) == 2 && os.Args[1] == "--inspect-runtime" {
		os.Exit(runRuntimeInspection(os.Stdin, os.Stdout))
	}
	if len(os.Args) == 2 && os.Args[1] == "--container-reference" {
		os.Exit(runContainerReference(os.Stdin, os.Stdout))
	}
	if len(os.Args) == 2 && os.Args[1] == "--container-build" {
		os.Exit(runContainerBuild(os.Stdin, os.Stdout))
	}
	if len(os.Args) == 2 && os.Args[1] == "--cvm-build" {
		os.Exit(runCVM(os.Stdin, os.Stdout))
	}
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	os.Exit(run(os.Stdin, os.Stdout, time.Now()))
}
