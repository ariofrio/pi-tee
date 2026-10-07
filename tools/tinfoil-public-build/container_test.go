package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Public build artifacts and a real Sigstore release signature, without a
// machine quote, credential, inference response or mocked verifier.
func TestPublicContainerBuild(t *testing.T) {
	input := map[string]any{"tag": "v0.0.25"}
	for field, name := range map[string]string{
		"deployment": "deployment", "index": "index", "imageManifest": "image",
		"imageConfig": "config", "attestationManifest": "attestation", "provenance": "provenance",
	} {
		raw, err := os.ReadFile("testdata/gemma-v0.0.25-" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		input[field] = base64.StdEncoding.EncodeToString(raw)
	}
	bundle, err := os.ReadFile("testdata/gemma-v0.0.25.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	input["bundle"] = json.RawMessage(bundle)
	selection, _ := json.Marshal(map[string]any{"tag": input["tag"], "deployment": input["deployment"], "bundle": input["bundle"]})
	var reference bytes.Buffer
	if runContainerReference(bytes.NewReader(selection), &reference) != 0 {
		t.Fatalf("signed image reference: %s", reference.String())
	}
	var selected map[string]any
	if json.Unmarshal(reference.Bytes(), &selected) != nil || selected["artifactReferenceVerified"] != true ||
		selected["imageDigest"] != "cb45fc53829f73b588c26fa9ca6c90be122367a64e3b835ce4571a4e5f839d89" || selected["inferenceQualified"] != false {
		t.Fatalf("incorrect image selection: %s", reference.String())
	}
	raw, _ := json.Marshal(input)
	var out bytes.Buffer
	if runContainerBuild(bytes.NewReader(raw), &out) != 0 {
		t.Fatalf("authentic public container: %s", out.String())
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["publisherEndorsedBuildMetadata"] != true || result["independentBuilderVerified"] != false || result["inferenceQualified"] != false ||
		result["imageDigest"] != "cb45fc53829f73b588c26fa9ca6c90be122367a64e3b835ce4571a4e5f839d89" ||
		result["dockerfileDigest"] != "6b097efe99c68966509662bd68566331cc3581791da091fb1127782265adcfd0" ||
		result["sourceCommit"] != "bff40cb8bd650c01be92e0f4cd98c960dbb222d9" ||
		result["releaseCommit"] != "43dc8f6d1c4d9c1504559ab181cf9dfe00ad239b" {
		t.Fatalf("incorrect authenticated artifact scope: %s", out.String())
	}
	for _, field := range []string{"deployment", "index", "imageManifest", "imageConfig", "attestationManifest", "provenance"} {
		t.Run("substituted "+field, func(t *testing.T) {
			var changed map[string]any
			json.Unmarshal(raw, &changed)
			artifact, _ := base64.StdEncoding.DecodeString(changed[field].(string))
			changed[field] = base64.StdEncoding.EncodeToString(append(artifact, '\n'))
			assertContainerRejection(t, changed)
		})
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"substituted release", func(i map[string]any) { i["tag"] = "v0.0.26" }},
		{"missing provenance", func(i map[string]any) { delete(i, "provenance") }},
		{"caller-selected publisher", func(i map[string]any) { i["repo"] = "attacker/model" }},
		{"forged publisher signature", func(i map[string]any) {
			var b map[string]any
			json.Unmarshal(bundle, &b)
			dsse := b["dsseEnvelope"].(map[string]any)
			payload, _ := base64.StdEncoding.DecodeString(dsse["payload"].(string))
			dsse["payload"] = base64.StdEncoding.EncodeToString(append(payload, '\n'))
			i["bundle"] = b
		}},
		{"relinked metadata cannot replace publisher authorization", func(i map[string]any) {
			proof, _ := base64.StdEncoding.DecodeString(i["provenance"].(string))
			proof = bytes.ReplaceAll(proof, []byte("bff40cb8bd650c01be92e0f4cd98c960dbb222d9"), []byte(strings.Repeat("a", 40)))
			i["provenance"] = base64.StdEncoding.EncodeToString(proof)
			attestation := decodeArtifactMap(t, i["attestationManifest"].(string))
			layer := attestation["layers"].([]any)[0].(map[string]any)
			layer["digest"] = "sha256:" + digest256(proof)
			layer["size"] = len(proof)
			attestationRaw, _ := json.Marshal(attestation)
			i["attestationManifest"] = base64.StdEncoding.EncodeToString(attestationRaw)
			index := decodeArtifactMap(t, i["index"].(string))
			for _, descriptor := range index["manifests"].([]any) {
				d := descriptor.(map[string]any)
				if d["annotations"] != nil {
					d["digest"] = "sha256:" + digest256(attestationRaw)
					d["size"] = len(attestationRaw)
				}
			}
			indexRaw, _ := json.Marshal(index)
			i["index"] = base64.StdEncoding.EncodeToString(indexRaw)
			deployment := decodeArtifactMap(t, i["deployment"].(string))
			config, _ := base64.StdEncoding.DecodeString(deployment["config"].(string))
			config = bytes.ReplaceAll(config, []byte("cb45fc53829f73b588c26fa9ca6c90be122367a64e3b835ce4571a4e5f839d89"), []byte(digest256(indexRaw)))
			deployment["config"] = base64.StdEncoding.EncodeToString(config)
			deploymentRaw, _ := json.Marshal(deployment)
			i["deployment"] = base64.StdEncoding.EncodeToString(deploymentRaw)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var changed map[string]any
			json.Unmarshal(raw, &changed)
			tc.change(changed)
			assertContainerRejection(t, changed)
		})
	}
}

func decodeArtifactMap(t *testing.T, encoded string) map[string]any {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("invalid test artifact")
	}
	return value
}

func assertContainerRejection(t *testing.T, input map[string]any) {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if runContainerBuild(bytes.NewReader(raw), &out) != 1 {
		t.Fatal("substitution accepted")
	}
	var failure map[string]any
	if json.Unmarshal(out.Bytes(), &failure) != nil || failure["failure"] != "TEE_CONTAINER_BUILD_REJECTED" || failure["publisherEndorsedBuildMetadata"] != false || failure["independentBuilderVerified"] != false || failure["inferenceQualified"] != false {
		t.Fatalf("unsafe failure scope: %s", out.String())
	}
}
