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
	input := map[string]any{"repo": "tinfoilsh/confidential-gemma4-31b", "tag": "v0.0.25"}
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
	selection, _ := json.Marshal(map[string]any{"repo": input["repo"], "tag": input["tag"], "deployment": input["deployment"], "bundle": input["bundle"]})
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

// A second publisher whose newer BuildKit writes OCI 1.1 attestation manifests
// (typed artifact, engine subject, inline empty config).
func TestPublicContainerBuildOCI11(t *testing.T) {
	input := map[string]any{"repo": "tinfoilsh/confidential-deepseek-v4-1-flash", "tag": "v0.0.3"}
	for field, name := range map[string]string{
		"deployment": "deployment", "index": "index", "imageManifest": "image",
		"imageConfig": "config", "attestationManifest": "attestation", "provenance": "provenance",
	} {
		raw, err := os.ReadFile("testdata/deepseek-v0.0.3-" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		input[field] = base64.StdEncoding.EncodeToString(raw)
	}
	bundle, err := os.ReadFile("testdata/deepseek-v0.0.3.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	input["bundle"] = json.RawMessage(bundle)
	raw, _ := json.Marshal(input)
	var out bytes.Buffer
	if runContainerBuild(bytes.NewReader(raw), &out) != 0 {
		t.Fatalf("authentic OCI 1.1 container: %s", out.String())
	}
	var result map[string]any
	if json.Unmarshal(out.Bytes(), &result) != nil || result["imageDigest"] != "fd77a686a50cc854424a55d6222530e6d5197d9b2f999ede32019b5dfd0ea9c0" ||
		result["sourceCommit"] != "c195341d2352c174220f85ebdfc8e4146c22e0e7" || result["releaseCommit"] != "0cc8920b9db0efa007c5bd6b57b9784f53fc71ff" {
		t.Fatalf("incorrect OCI 1.1 scope: %s", out.String())
	}
	// The attestation must name the engine manifest it describes.
	attestation, _ := os.ReadFile("testdata/deepseek-v0.0.3-attestation.json")
	changed := strings.Replace(string(attestation), "a28f300c5465f34d8e3f76d2979ae1cccb9a978a1af619ad9cf11e852b79ac28", strings.Repeat("b", 64), 1)
	if changed == string(attestation) {
		t.Fatal("mutation did not apply")
	}
	var index map[string]any
	indexRaw, _ := os.ReadFile("testdata/deepseek-v0.0.3-index.json")
	json.Unmarshal(indexRaw, &index)
	for _, item := range index["manifests"].([]any) {
		descriptor := item.(map[string]any)
		if descriptor["platform"].(map[string]any)["os"] == "unknown" {
			descriptor["digest"] = "sha256:" + digest256([]byte(changed))
			descriptor["size"] = len(changed)
		}
	}
	rewritten, _ := json.Marshal(index)
	input["attestationManifest"] = base64.StdEncoding.EncodeToString([]byte(changed))
	input["index"] = base64.StdEncoding.EncodeToString(rewritten)
	raw, _ = json.Marshal(input)
	out.Reset()
	if runContainerBuild(bytes.NewReader(raw), &out) == 0 {
		t.Fatal("attestation for another manifest admitted")
	}
}
