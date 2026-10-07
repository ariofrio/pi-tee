package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// Same finite root set as the workload verifier; no root discovery or updates.
//
//go:embed trusted_root.json
var cvmTrustedRoot []byte

const cvmRepo = "tinfoilsh/cvmimage"

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)

type cvmInput struct {
	Tag      string          `json:"tag"`
	Manifest string          `json:"manifest"`
	Bundle   json.RawMessage `json:"bundle"`
}

type cvmManifest struct {
	Version string `json:"version"`
	Root    string `json:"root"`
	Initrd  string `json:"initrd"`
	Kernel  string `json:"kernel"`
	Raw     string `json:"raw"`
}

type cvmResult struct {
	CVMBuildVerified   bool        `json:"cvmBuildVerified"`
	InferenceQualified bool        `json:"inferenceQualified"`
	Repo               string      `json:"repo"`
	Workflow           string      `json:"workflow"`
	Commit             string      `json:"commit"`
	ManifestDigest     string      `json:"manifestDigest"`
	Hashes             cvmManifest `json:"hashes"`
}

func decodeOne(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func authenticateCVM(i *cvmInput) (*cvmResult, error) {
	rejected := errors.New("TEE_CVM_BUILD_REJECTED")
	if !stableTag.MatchString(i.Tag) {
		return nil, rejected
	}
	manifest, err := base64.StdEncoding.Strict().DecodeString(i.Manifest)
	if err != nil || len(manifest) > 8192 {
		return nil, rejected
	}
	var hashes cvmManifest
	if decodeOne(manifest, &hashes) != nil || hashes.Version != i.Tag {
		return nil, rejected
	}
	for _, digest := range []string{hashes.Root, hashes.Initrd, hashes.Kernel, hashes.Raw} {
		if !digestPattern.MatchString(digest) {
			return nil, rejected
		}
	}
	sum := sha256.Sum256(manifest)
	expected := "https://github.com/" + cvmRepo + "/.github/workflows/release.yml@refs/tags/" + i.Tag
	var b bundle.Bundle
	if b.UnmarshalJSON(i.Bundle) != nil || b.GetMediaType() != "application/vnd.dev.sigstore.bundle.v0.3+json" ||
		b.GetDsseEnvelope() == nil || len(b.GetDsseEnvelope().GetSignatures()) != 1 {
		return nil, rejected
	}
	cert, err := x509.ParseCertificate(b.GetVerificationMaterial().GetCertificate().GetRawBytes())
	if err != nil || len(cert.URIs) != 1 || cert.URIs[0].String() != expected {
		return nil, rejected
	}
	ext, err := certificate.ParseExtensions(cert.Extensions)
	if err != nil || ext.SourceRepositoryURI != "https://github.com/"+cvmRepo ||
		ext.SourceRepositoryRef != "refs/tags/"+i.Tag || ext.BuildSignerURI != expected ||
		ext.SourceRepositoryVisibilityAtSigning != "public" || ext.RunnerEnvironment != "github-hosted" ||
		!commitPattern.MatchString(ext.SourceRepositoryDigest) || ext.BuildSignerDigest != ext.SourceRepositoryDigest {
		return nil, rejected
	}
	trusted, err := root.NewTrustedRootFromJSON(cvmTrustedRoot)
	if err != nil {
		return nil, rejected
	}
	v, err := sigverify.NewSignedEntityVerifier(trusted, sigverify.WithSignedCertificateTimestamps(1),
		sigverify.WithTransparencyLog(1), sigverify.WithObserverTimestamps(1))
	if err != nil {
		return nil, rejected
	}
	identity, err := sigverify.NewShortCertificateIdentity("https://token.actions.githubusercontent.com", "", expected, "")
	if err != nil {
		return nil, rejected
	}
	verified, err := v.Verify(&b, sigverify.NewPolicy(sigverify.WithArtifactDigest("sha256", sum[:]), sigverify.WithCertificateIdentity(identity)))
	if err != nil || verified.Statement == nil || verified.Statement.PredicateType != "https://slsa.dev/provenance/v1" ||
		verified.Statement.Type != "https://in-toto.io/Statement/v1" {
		return nil, rejected
	}
	// GitHub's build statement legitimately has multiple artifacts. Require each
	// exact artifact name once, with one SHA256 digest, from this same build.
	wanted := map[string]string{
		"tinfoil-inference-" + i.Tag + "-manifest.json": hex.EncodeToString(sum[:]),
		"tinfoil-inference-" + i.Tag + ".vmlinuz":       hashes.Kernel,
		"tinfoil-inference-" + i.Tag + ".initrd":        hashes.Initrd,
		"tinfoil-inference-" + i.Tag + ".raw":           hashes.Raw,
	}
	seen := map[string]bool{}
	for _, subject := range verified.Statement.Subject {
		if digest, ok := wanted[subject.Name]; ok {
			if seen[subject.Name] || len(subject.Digest) != 1 || subject.Digest["sha256"] != digest {
				return nil, rejected
			}
			seen[subject.Name] = true
		}
	}
	if len(seen) != len(wanted) {
		return nil, rejected
	}
	// Bind build inputs to the certificate's authenticated source commit.
	p := verified.Statement.Predicate.AsMap()
	definition, ok := p["buildDefinition"].(map[string]any)
	if !ok || definition["buildType"] != "https://actions.github.io/buildtypes/workflow/v1" {
		return nil, rejected
	}
	parameters, ok := definition["externalParameters"].(map[string]any)
	if !ok {
		return nil, rejected
	}
	workflow, ok := parameters["workflow"].(map[string]any)
	if !ok || workflow["repository"] != "https://github.com/"+cvmRepo || workflow["ref"] != "refs/tags/"+i.Tag ||
		workflow["path"] != ".github/workflows/release.yml" {
		return nil, rejected
	}
	dependencies, ok := definition["resolvedDependencies"].([]any)
	if !ok || len(dependencies) != 1 {
		return nil, rejected
	}
	dep, ok := dependencies[0].(map[string]any)
	if !ok || dep["uri"] != "git+https://github.com/"+cvmRepo+"@refs/tags/"+i.Tag {
		return nil, rejected
	}
	digest, ok := dep["digest"].(map[string]any)
	if !ok || len(digest) != 1 || digest["gitCommit"] != ext.SourceRepositoryDigest {
		return nil, rejected
	}
	details, ok := p["runDetails"].(map[string]any)
	if !ok {
		return nil, rejected
	}
	builder, ok := details["builder"].(map[string]any)
	if !ok || builder["id"] != expected {
		return nil, rejected
	}
	return &cvmResult{CVMBuildVerified: true, Repo: cvmRepo, Workflow: "release.yml", Commit: ext.SourceRepositoryDigest,
		ManifestDigest: hex.EncodeToString(sum[:]), Hashes: hashes}, nil
}

func runCVM(reader io.Reader, writer io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	var i cvmInput
	if err == nil && len(raw) <= maxInputBytes {
		err = decodeOne(raw, &i)
	} else {
		err = errors.New("input rejected")
	}
	var verified *cvmResult
	if err == nil {
		verified, err = authenticateCVM(&i)
	}
	if err != nil {
		json.NewEncoder(writer).Encode(map[string]any{"cvmBuildVerified": false, "inferenceQualified": false, "failure": "TEE_CVM_BUILD_REJECTED"})
		return 1
	}
	if json.NewEncoder(writer).Encode(verified) != nil {
		return 1
	}
	return 0
}
