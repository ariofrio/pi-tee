package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The public inspection CLI checks configuration constraints, without a mocked
// publisher or hardware verifier and without claiming release authentication.
func TestInspectRuntimeConstraints(t *testing.T) {
	raw, err := os.ReadFile("testdata/gemma-v0.0.25-deployment.json")
	if err != nil {
		t.Fatal(err)
	}
	var deployment struct {
		Config string `json:"config"`
	}
	if json.Unmarshal(raw, &deployment) != nil {
		t.Fatal("invalid public fixture")
	}
	input, _ := json.Marshal(map[string]any{"config": deployment.Config})
	var out bytes.Buffer
	if runRuntimeInspection(bytes.NewReader(input), &out) != 0 {
		t.Fatalf("supported public configuration: %s", out.String())
	}
	var result map[string]any
	if json.Unmarshal(out.Bytes(), &result) != nil || result["runtimeConstraintsVerified"] != true || result["authenticatedRelease"] != false || result["inferenceQualified"] != false || result["profile"] != "gemma-single-gpu-v1" {
		t.Fatalf("incorrect inspection scope: %s", out.String())
	}
	packs := result["modelPacks"].([]any)
	if len(packs) != 2 || packs[0].(map[string]any)["verityRoot"] != "cda2f261f72d80a847eb6fabea1f9949bf14ce5bb323808a8e2e4a9f09018357" {
		t.Fatal("model-pack binding lost")
	}
}

func TestInspectRuntimeRejectsUnsafeConfiguration(t *testing.T) {
	raw, err := os.ReadFile("testdata/gemma-v0.0.25-deployment.json")
	if err != nil {
		t.Fatal(err)
	}
	var deployment struct {
		Config string `json:"config"`
	}
	if json.Unmarshal(raw, &deployment) != nil {
		t.Fatal("invalid public fixture")
	}
	config, err := base64.StdEncoding.DecodeString(deployment.Config)
	if err != nil {
		t.Fatal(err)
	}
	base := string(config)
	cases := map[string]string{
		"inherited environment":     strings.Replace(base, `- VLLM_USE_V2_MODEL_RUNNER: "0"`, `- VLLM_USE_V2_MODEL_RUNNER`, 1),
		"unknown CC environment":    strings.Replace(base, `- VLLM_CC_PAGEABLE_H2D: "1"`, `- VLLM_CC_LOG_MODEL_INPUTS: "1"`, 1),
		"host mount":                strings.Replace(base, "    runtime: nvidia", "    volumes: [\"/host:/data\"]\n    runtime: nvidia", 1),
		"writable root":             strings.Replace(base, "    runtime: nvidia", "    read_only: false\n    runtime: nvidia", 1),
		"network escape":            strings.Replace(base, "    runtime: nvidia", "    networks: [default]\n    runtime: nvidia", 1),
		"privileged":                strings.Replace(base, "    runtime: nvidia", "    privileged: true\n    runtime: nvidia", 1),
		"host namespaces":           strings.Replace(base, "    runtime: nvidia", "    pid: host\n    runtime: nvidia", 1),
		"vault":                     base + "\nvault: {url: https://example.invalid}\n",
		"remote code":               strings.Replace(base, `"--port", "8001"`, `"--trust-remote-code", "--port", "8001"`, 1),
		"request logging":           strings.Replace(base, `"--port", "8001"`, `"--enable-log-requests", "--port", "8001"`, 1),
		"mutable model source":      strings.Replace(base, "@842da3794eaa0b77d5f08bae87a17459d91ff475", "@main", 1),
		"different model root":      strings.Replace(base, "cda2f261f72d80a847eb6fabea1f9949bf14ce5bb323808a8e2e4a9f09018357_", strings.Repeat("a", 64)+"_", 1),
		"upstream mismatch":         strings.Replace(base, "upstream-port: 8001", "upstream-port: 8002", 1),
		"unauthenticated chat":      strings.Replace(base, "authenticated: true", "authenticated: false", 1),
		"health argument ambiguity": strings.Replace(base, `["CMD", "curl", "-sf", "http://localhost:8001/health"]`, `["CMD\0curl", "-sf", "http://localhost:8001/health"]`, 1),
		"duplicate key":             base + "\ngpus: 1\n",
		"alias":                     strings.Replace(base, "cpus: 16", "cpus: &cpu 16", 1),
		"merge":                     base + "\n<<: {gpus: 1}\n",
		"second document":           base + "\n---\ngpus: 1\n",
	}
	for name, changed := range cases {
		t.Run(name, func(t *testing.T) {
			if changed == base {
				t.Fatal("mutation did not apply")
			}
			input, _ := json.Marshal(map[string]any{"config": base64.StdEncoding.EncodeToString([]byte(changed))})
			var out bytes.Buffer
			if runRuntimeInspection(bytes.NewReader(input), &out) != 1 {
				t.Fatalf("unsafe configuration accepted: %s", out.String())
			}
			var result map[string]any
			if json.Unmarshal(out.Bytes(), &result) != nil || result["failure"] != "TEE_RUNTIME_CONFIG_REJECTED" || result["runtimeConstraintsVerified"] != false || result["authenticatedRelease"] != false || result["inferenceQualified"] != false {
				t.Fatalf("incorrect rejection: %s", out.String())
			}
		})
	}
}

func TestRuntimeAuthenticatesRelease(t *testing.T) {
	deployment, err := os.ReadFile("testdata/gemma-v0.0.25-deployment.json")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile("testdata/gemma-v0.0.25.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"tag": "v0.0.25", "deployment": base64.StdEncoding.EncodeToString(deployment), "bundle": json.RawMessage(bundle)}
	encoded, _ := json.Marshal(input)
	var out bytes.Buffer
	if runRuntimeRelease(bytes.NewReader(encoded), &out) != 0 {
		t.Fatalf("authentic constrained release: %s", out.String())
	}
	var result map[string]any
	if json.Unmarshal(out.Bytes(), &result) != nil || result["authenticatedRelease"] != true || result["runtimeConstraintsVerified"] != true || result["inferenceQualified"] != false || result["freshnessVerified"] != false || result["cpuVerified"] != false || result["releaseCommit"] != "43dc8f6d1c4d9c1504559ab181cf9dfe00ad239b" || result["deploymentDigest"] != "65f2dfa59ced010aeba841fc909880ac3434282cf2b43e90d5c3a3e543b3ccf0" {
		t.Fatalf("incorrect authenticated scope: %s", out.String())
	}
	for _, name := range []string{"tag", "deployment", "bundle", "repo"} {
		t.Run("substituted "+name, func(t *testing.T) {
			var changed map[string]any
			json.Unmarshal(encoded, &changed)
			switch name {
			case "tag":
				changed[name] = "v0.0.26"
			case "deployment":
				changed[name] = base64.StdEncoding.EncodeToString(append(append([]byte{}, deployment...), '\n'))
			case "bundle":
				changed[name] = map[string]any{}
			case "repo":
				changed[name] = "attacker/workload"
			}
			raw, _ := json.Marshal(changed)
			var rejected bytes.Buffer
			if runRuntimeRelease(bytes.NewReader(raw), &rejected) != 1 {
				t.Fatalf("substitution admitted: %s", rejected.String())
			}
			var failure map[string]any
			if json.Unmarshal(rejected.Bytes(), &failure) != nil || failure["authenticatedRelease"] != false || failure["runtimeConstraintsVerified"] != false || failure["inferenceQualified"] != false || failure["failure"] != "TEE_RUNTIME_CONFIG_REJECTED" {
				t.Fatalf("incorrect rejection: %s", rejected.String())
			}
		})
	}
}

func TestRuntimeConstraintsDoNotFreezeArtifactDigests(t *testing.T) {
	raw, err := os.ReadFile("testdata/gemma-v0.0.25-deployment.json")
	if err != nil {
		t.Fatal(err)
	}
	var deployment struct {
		Config string `json:"config"`
	}
	if json.Unmarshal(raw, &deployment) != nil {
		t.Fatal("invalid public fixture")
	}
	config, _ := base64.StdEncoding.DecodeString(deployment.Config)
	changed := string(config)
	for old, next := range map[string]string{
		"cvm-version: 0.11.0": "cvm-version: 1.2.3",
		"cb45fc53829f73b588c26fa9ca6c90be122367a64e3b835ce4571a4e5f839d89": strings.Repeat("b", 64),
		"cda2f261f72d80a847eb6fabea1f9949bf14ce5bb323808a8e2e4a9f09018357": strings.Repeat("c", 64),
		"842da3794eaa0b77d5f08bae87a17459d91ff475":                         strings.Repeat("d", 40),
	} {
		changed = strings.ReplaceAll(changed, old, next)
	}
	input, _ := json.Marshal(map[string]any{"config": base64.StdEncoding.EncodeToString([]byte(changed))})
	var out bytes.Buffer
	if runRuntimeInspection(bytes.NewReader(input), &out) != 0 {
		t.Fatalf("dynamic inspection: %s", out.String())
	}
	var result map[string]any
	if json.Unmarshal(out.Bytes(), &result) != nil || result["authenticatedRelease"] != false || result["runtimeConstraintsVerified"] != true || result["inferenceQualified"] != false || result["imageDigest"] != strings.Repeat("b", 64) || result["cvmTag"] != "v1.2.3" {
		t.Fatalf("dynamic constraints scope: %s", out.String())
	}
}
