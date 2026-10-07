package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"go.yaml.in/yaml/v3"
)

const ociImage = "application/vnd.oci.image.manifest.v1+json"
const ociIndex = "application/vnd.oci.image.index.v1+json"
const ociConfig = "application/vnd.oci.image.config.v1+json"
const slsaV1 = "https://slsa.dev/provenance/v1"

type containerInput struct {
	Tag                 string          `json:"tag"`
	Deployment          string          `json:"deployment"`
	Bundle              json.RawMessage `json:"bundle"`
	Index               string          `json:"index"`
	ImageManifest       string          `json:"imageManifest"`
	ImageConfig         string          `json:"imageConfig"`
	AttestationManifest string          `json:"attestationManifest"`
	Provenance          string          `json:"provenance"`
}

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	} `json:"platform"`
	Annotations map[string]string `json:"annotations"`
}

type ociDocument struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociDescriptor `json:"manifests"`
	Config        ociDescriptor   `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
}

func bytes64(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > 128*1024 || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("artifact encoding")
	}
	return raw, nil
}
func digest256(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func matchesDescriptor(raw []byte, descriptor ociDescriptor, mediaType string) bool {
	return descriptor.MediaType == mediaType && descriptor.Size == int64(len(raw)) && descriptor.Digest == "sha256:"+digest256(raw)
}
func validDescriptor(d ociDescriptor) bool {
	return strings.HasPrefix(d.Digest, "sha256:") && digestPattern.MatchString(strings.TrimPrefix(d.Digest, "sha256:")) && d.Size > 0 && d.Size <= 32*1024*1024*1024
}

// The named release publisher endorses the OCI root. Embedded BuildKit claims
// inherit that endorsement; they are NOT an independent builder signature.
func authenticatedContainerReference(tag, deployment64 string, releaseBundle []byte) (*provenance.Code, string, error) {
	rejected := errors.New("TEE_CONTAINER_BUILD_REJECTED")
	deployment, err := bytes64(deployment64)
	if err != nil {
		return nil, "", rejected
	}
	code, release, _, err := authenticateDeployment(tag, deployment, releaseBundle)
	if err != nil {
		return nil, "", rejected
	}
	config, err := bytes64(release.Config)
	if err != nil {
		return nil, "", rejected
	}
	var selected struct {
		Containers []struct {
			Name  string `yaml:"name"`
			Image string `yaml:"image"`
		} `yaml:"containers"`
	}
	if yaml.Unmarshal(config, &selected) != nil || len(selected.Containers) != 1 || selected.Containers[0].Name != "gemma4-31b" {
		return nil, "", rejected
	}
	prefix := "ghcr.io/" + codeRepo + "@sha256:"
	image := selected.Containers[0].Image
	if !strings.HasPrefix(image, prefix) || !digestPattern.MatchString(strings.TrimPrefix(image, prefix)) {
		return nil, "", rejected
	}
	return code, strings.TrimPrefix(image, prefix), nil
}

func authenticateContainer(i *containerInput) (map[string]any, error) {
	rejected := errors.New("TEE_CONTAINER_BUILD_REJECTED")
	code, imageDigest, err := authenticatedContainerReference(i.Tag, i.Deployment, i.Bundle)
	if err != nil {
		return nil, rejected
	}
	indexRaw, err := bytes64(i.Index)
	if err != nil || digest256(indexRaw) != imageDigest {
		return nil, rejected
	}
	var index ociDocument
	if decodeOne(indexRaw, &index) != nil || index.SchemaVersion != 2 || index.MediaType != ociIndex || len(index.Manifests) != 2 {
		return nil, rejected
	}
	var engine, attestation *ociDescriptor
	for n := range index.Manifests {
		d := &index.Manifests[n]
		if !validDescriptor(*d) || d.MediaType != ociImage {
			return nil, rejected
		}
		if d.Platform.Architecture == "amd64" && d.Platform.OS == "linux" && engine == nil && d.Annotations["vnd.docker.reference.type"] == "" {
			engine = d
		} else if d.Platform.Architecture == "unknown" && d.Platform.OS == "unknown" && attestation == nil && d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			attestation = d
		} else {
			return nil, rejected
		}
	}
	if engine == nil || attestation == nil || attestation.Annotations["vnd.docker.reference.digest"] != engine.Digest {
		return nil, rejected
	}
	imageRaw, err := bytes64(i.ImageManifest)
	if err != nil || !matchesDescriptor(imageRaw, *engine, ociImage) {
		return nil, rejected
	}
	attestationRaw, err := bytes64(i.AttestationManifest)
	if err != nil || !matchesDescriptor(attestationRaw, *attestation, ociImage) {
		return nil, rejected
	}
	var im, am ociDocument
	if decodeOne(imageRaw, &im) != nil || decodeOne(attestationRaw, &am) != nil || im.SchemaVersion != 2 || am.SchemaVersion != 2 || im.MediaType != ociImage || am.MediaType != ociImage || len(im.Layers) == 0 || len(im.Layers) > 256 || len(am.Layers) != 1 {
		return nil, rejected
	}
	for _, layer := range im.Layers {
		if !validDescriptor(layer) {
			return nil, rejected
		}
	}
	configRaw, err := bytes64(i.ImageConfig)
	if err != nil || !matchesDescriptor(configRaw, im.Config, ociConfig) {
		return nil, rejected
	}
	proofRaw, err := bytes64(i.Provenance)
	if err != nil || !matchesDescriptor(proofRaw, am.Layers[0], "application/vnd.in-toto+json") || am.Layers[0].Annotations["in-toto.io/predicate-type"] != slsaV1 {
		return nil, rejected
	}
	var imageConfig struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		Config       struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if strictDecode(configRaw, &imageConfig, true) != nil || imageConfig.Architecture != "amd64" || imageConfig.OS != "linux" {
		return nil, rejected
	}
	var statement struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate struct {
			BuildDefinition struct {
				BuildType          string `json:"buildType"`
				ExternalParameters struct {
					ConfigSource struct {
						Path string `json:"path"`
					} `json:"configSource"`
					Request struct {
						Args map[string]string `json:"args"`
						Root struct {
							Request struct {
								Args map[string]string `json:"args"`
							} `json:"request"`
						} `json:"root"`
					} `json:"request"`
				} `json:"externalParameters"`
			} `json:"buildDefinition"`
			RunDetails struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
				Metadata struct {
					Buildkit struct {
						VCS    map[string]string `json:"vcs"`
						Source struct {
							Infos []struct {
								Filename string `json:"filename"`
								Language string `json:"language"`
								Data     string `json:"data"`
							} `json:"infos"`
						} `json:"source"`
					} `json:"buildkit_metadata"`
				} `json:"metadata"`
			} `json:"runDetails"`
		} `json:"predicate"`
	}
	if strictDecode(proofRaw, &statement, true) != nil || statement.Type != "https://in-toto.io/Statement/v1" || statement.PredicateType != slsaV1 || len(statement.Subject) == 0 || len(statement.Subject) > 16 {
		return nil, rejected
	}
	for _, subject := range statement.Subject {
		if len(subject.Digest) != 1 || "sha256:"+subject.Digest["sha256"] != engine.Digest || !strings.HasPrefix(subject.Name, "pkg:docker/ghcr.io/"+codeRepo+"@") {
			return nil, rejected
		}
	}
	definition := statement.Predicate.BuildDefinition
	args := definition.ExternalParameters.Request.Args
	vcs := definition.ExternalParameters.Request.Root.Request.Args
	metadata := statement.Predicate.RunDetails.Metadata.Buildkit.VCS
	source := imageConfig.Config.Labels["org.opencontainers.image.revision"]
	sourceURL := "https://github.com/" + codeRepo
	builder := statement.Predicate.RunDetails.Builder.ID
	if definition.BuildType != "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md" || definition.ExternalParameters.ConfigSource.Path != "Dockerfile" || !commitPattern.MatchString(source) ||
		imageConfig.Config.Labels["org.opencontainers.image.source"] != sourceURL ||
		args["build-arg:SOURCE_REVISION"] != source || args["build-arg:VERSION"] != i.Tag || args["label:org.opencontainers.image.revision"] != source || args["label:org.opencontainers.image.source"] != sourceURL ||
		vcs["vcs:revision"] != source || vcs["vcs:source"] != sourceURL || metadata["revision"] != source || metadata["source"] != sourceURL ||
		!regexp.MustCompile(`^https://github\.com/tinfoilsh/confidential-gemma4-31b/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*$`).MatchString(builder) {
		return nil, rejected
	}
	infos := statement.Predicate.RunDetails.Metadata.Buildkit.Source.Infos
	if len(infos) != 1 || infos[0].Filename != "Dockerfile" || infos[0].Language != "Dockerfile" {
		return nil, rejected
	}
	dockerfile, err := bytes64(infos[0].Data)
	if err != nil {
		return nil, rejected
	}
	_, statementDigest, err := codePredicate(i.Bundle, code)
	if err != nil {
		return nil, rejected
	}
	return map[string]any{
		"subjectPredicateMatched": true, "codeStatementDigest": statementDigest,
		"publisherEndorsedBuildMetadata": true, "independentBuilderVerified": false, "freshnessVerified": false,
		"cpuVerified": false, "gpuVerified": false, "inferenceQualified": false,
		"repo": codeRepo, "tag": code.Tag, "releaseCommit": code.Commit, "deploymentDigest": code.Digest,
		"imageDigest": imageDigest, "imageManifestDigest": strings.TrimPrefix(engine.Digest, "sha256:"),
		"provenanceDigest": digest256(proofRaw), "sourceCommit": source, "builderClaim": builder,
		"dockerfileDigest": digest256(dockerfile),
	}, nil
}

func runContainerBuild(reader io.Reader, writer io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	var input containerInput
	var result map[string]any
	if err == nil && len(raw) <= maxInputBytes && decodeOne(raw, &input) == nil {
		result, err = authenticateContainer(&input)
	} else {
		err = errors.New("input")
	}
	if err != nil {
		json.NewEncoder(writer).Encode(map[string]any{"publisherEndorsedBuildMetadata": false, "independentBuilderVerified": false, "inferenceQualified": false, "failure": "TEE_CONTAINER_BUILD_REJECTED"})
		return 1
	}
	if json.NewEncoder(writer).Encode(result) != nil {
		return 1
	}
	return 0
}

type containerReferenceInput struct {
	Tag        string          `json:"tag"`
	Deployment string          `json:"deployment"`
	Bundle     json.RawMessage `json:"bundle"`
}

func runContainerReference(reader io.Reader, writer io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	var input containerReferenceInput
	if err == nil && len(raw) <= maxInputBytes && decodeOne(raw, &input) == nil {
		code, digest, checked := authenticatedContainerReference(input.Tag, input.Deployment, input.Bundle)
		if checked == nil {
			_, statementDigest, err := codePredicate(input.Bundle, code)
			if err == nil && json.NewEncoder(writer).Encode(map[string]any{"artifactReferenceVerified": true, "subjectPredicateMatched": true, "codeStatementDigest": statementDigest, "freshnessVerified": false, "inferenceQualified": false, "repo": code.Repo, "tag": code.Tag, "releaseCommit": code.Commit, "deploymentDigest": code.Digest, "imageDigest": digest}) == nil {
				return 0
			}
		}
	}
	json.NewEncoder(writer).Encode(map[string]any{"artifactReferenceVerified": false, "inferenceQualified": false, "failure": "TEE_CONTAINER_BUILD_REJECTED"})
	return 1
}
