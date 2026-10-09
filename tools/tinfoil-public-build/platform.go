package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

const platformV2 = "https://tinfoil.sh/predicate/platform-endorsements/v2"

var platformTag = regexp.MustCompile(`^platform-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var platformRun = regexp.MustCompile(`^https://github.com/tinfoilsh/cvmimage/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*$`)

type platformCompanion struct {
	Digest string          `json:"digest"`
	Bundle json.RawMessage `json:"bundle"`
}
type platformStatement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

func platformIdentity(raw []byte, repo, tag string) (*bundle.Bundle, *certificate.Extensions, error) {
	reject := errors.New("TEE_PLATFORM_REFERENCE_REJECTED")
	if repo != cvmRepo || !platformTag.MatchString(tag) {
		return nil, nil, reject
	}
	var b bundle.Bundle
	if b.UnmarshalJSON(raw) != nil || b.GetMediaType() != "application/vnd.dev.sigstore.bundle.v0.3+json" || b.GetDsseEnvelope() == nil || len(b.GetDsseEnvelope().GetSignatures()) != 1 {
		return nil, nil, reject
	}
	expected := "https://github.com/" + cvmRepo + "/.github/workflows/platform-release.yml@refs/tags/" + tag
	cert, err := x509.ParseCertificate(b.GetVerificationMaterial().GetCertificate().GetRawBytes())
	if err != nil || len(cert.URIs) != 1 || cert.URIs[0].String() != expected {
		return nil, nil, reject
	}
	ext, err := certificate.ParseExtensions(cert.Extensions)
	if err != nil || ext.SourceRepositoryURI != "https://github.com/"+cvmRepo || ext.SourceRepositoryRef != "refs/tags/"+tag || ext.BuildSignerURI != expected || ext.SourceRepositoryVisibilityAtSigning != "public" || ext.RunnerEnvironment != "github-hosted" || !commitPattern.MatchString(ext.SourceRepositoryDigest) || ext.BuildSignerDigest != ext.SourceRepositoryDigest || !platformRun.MatchString(ext.RunInvocationURI) {
		return nil, nil, reject
	}
	return &b, &ext, nil
}

func authenticatePlatformStatement(raw []byte, repo, tag, digest string) (*platformStatement, *certificate.Extensions, error) {
	reject := errors.New("TEE_PLATFORM_REFERENCE_REJECTED")
	b, ext, err := platformIdentity(raw, repo, tag)
	if err != nil {
		return nil, nil, reject
	}
	sum, err := hex.DecodeString(digest)
	if err != nil || !digestPattern.MatchString(digest) {
		return nil, nil, reject
	}
	trusted, err := root.NewTrustedRootFromJSON(cvmTrustedRoot)
	if err != nil {
		return nil, nil, reject
	}
	verifier, err := sigverify.NewSignedEntityVerifier(trusted, sigverify.WithSignedCertificateTimestamps(1), sigverify.WithTransparencyLog(1), sigverify.WithObserverTimestamps(1))
	if err != nil {
		return nil, nil, reject
	}
	identity, err := sigverify.NewShortCertificateIdentity("https://token.actions.githubusercontent.com", "", ext.BuildSignerURI, "")
	if err != nil {
		return nil, nil, reject
	}
	verified, err := verifier.Verify(b, sigverify.NewPolicy(sigverify.WithArtifactDigest("sha256", sum), sigverify.WithCertificateIdentity(identity)))
	if err != nil || verified.Statement == nil {
		return nil, nil, reject
	}
	var statement platformStatement
	if decodeOne(b.GetDsseEnvelope().GetPayload(), &statement) != nil || statement.Type != "https://in-toto.io/Statement/v1" || len(statement.Subject) != 1 || len(statement.Subject[0].Digest) != 1 || statement.Subject[0].Digest["sha256"] != digest {
		return nil, nil, reject
	}
	expected := "platform-endorsements.json"
	if statement.PredicateType == policy.ArtifactFormat {
		expected = "platform-endorsements-classic.json"
	} else if statement.PredicateType != platformV2 {
		return nil, nil, reject
	}
	if statement.Subject[0].Name != expected {
		return nil, nil, reject
	}
	return &statement, ext, nil
}

// A v2 projection cannot authorize missing classic boot constraints; authenticate its same-tag/run/source companion separately.
func authenticatePlatform(raw []byte, repo, tag, digest string, classic *platformCompanion) (*provenance.PlatformEndorsements, error) {
	reject := errors.New("TEE_PLATFORM_REFERENCE_REJECTED")
	statement, ext, err := authenticatePlatformStatement(raw, repo, tag, digest)
	if err != nil {
		return nil, reject
	}
	var artifact *policy.Artifact
	if statement.PredicateType == policy.ArtifactFormat {
		artifact, err = policy.Parse(statement.Predicate)
	} else {
		if classic == nil {
			return nil, errors.New("TEE_PLATFORM_CLASSIC_REQUIRED")
		}
		companion, classicExt, companionErr := authenticatePlatformStatement(classic.Bundle, repo, tag, classic.Digest)
		if companionErr != nil || companion.PredicateType != policy.ArtifactFormat || classicExt.RunInvocationURI != ext.RunInvocationURI || classicExt.SourceRepositoryDigest != ext.SourceRepositoryDigest {
			return nil, reject
		}
		artifact, err = mergePlatformV2(statement.Predicate, companion.Predicate)
	}
	if err != nil || artifact == nil {
		return nil, reject
	}
	return &provenance.PlatformEndorsements{AuthenticatedArtifact: provenance.AuthenticatedArtifact{Repo: repo, Tag: tag, Commit: ext.SourceRepositoryDigest, Digest: digest, SubjectName: statement.Subject[0].Name}, Artifact: artifact}, nil
}

// v2 removes classic boot constraints. Preserve them from a separately signed
// companion in the same release/run; require the exact publisher transform.
func mergePlatformV2(runtime, classic []byte) (*policy.Artifact, error) {
	reject := errors.New("TEE_PLATFORM_REFERENCE_REJECTED")
	artifact, err := policy.Parse(classic)
	if err != nil {
		return nil, reject
	}
	var v2 struct {
		Format   string                   `json:"format"`
		Machines map[string]string        `json:"machines"`
		Policies map[string]policy.Policy `json:"policies"`
	}
	if decodeOne(runtime, &v2) != nil || v2.Format != platformV2 {
		return nil, reject
	}
	var expected, actual map[string]any
	if json.Unmarshal(classic, &expected) != nil || json.Unmarshal(runtime, &actual) != nil || expected == nil || actual == nil {
		return nil, reject
	}
	policies, ok := expected["policies"].(map[string]any)
	if !ok || policies == nil {
		return nil, reject
	}
	expected["format"] = platformV2
	delete(expected, "measurements")
	for name, p := range artifact.Policies {
		block, ok := policies[name].(map[string]any)
		if !ok || block == nil {
			return nil, reject
		}
		switch p.Platform {
		case policy.PlatformTDX:
			tdx, ok := block["tdx"].(map[string]any)
			if !ok || tdx == nil || p.TDX == nil {
				return nil, reject
			}
			delete(tdx, "platform_measurements")
		case policy.PlatformSEVSNP:
			snp, ok := block["sev_snp"].(map[string]any)
			if !ok || snp == nil || p.SEVSNP == nil {
				return nil, reject
			}
			delete(snp, "host_data")
			parts := strings.Split(p.SEVSNP.MinimumABIVersion, ".")
			if len(parts) != 2 {
				return nil, reject
			}
			major, majorErr := strconv.Atoi(parts[0])
			minor, minorErr := strconv.Atoi(parts[1])
			if majorErr != nil || minorErr != nil || major < 0 || major > 255 || minor < 0 || minor > 255 {
				return nil, reject
			}
			if major < 1 || major == 1 && minor < 51 {
				p.SEVSNP.MinimumABIVersion = "1.51"
			}
			snp["minimum_abi_version"] = p.SEVSNP.MinimumABIVersion
		default:
			return nil, reject
		}
	}
	if !reflect.DeepEqual(expected, actual) {
		return nil, reject
	}
	// Revalidate with all classic boot fields retained and v2's ABI floor applied.
	merged, err := json.Marshal(artifact)
	if err != nil {
		return nil, reject
	}
	return policy.Parse(merged)
}
