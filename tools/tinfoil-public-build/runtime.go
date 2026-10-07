package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

const runtimeProfile = "gemma-single-gpu-v1"

type runtimeConfig struct {
	CVMVersion string             `yaml:"cvm-version"`
	CPUs       int                `yaml:"cpus"`
	Memory     int                `yaml:"memory"`
	GPUs       int                `yaml:"gpus"`
	Models     []runtimeModel     `yaml:"models"`
	Containers []runtimeContainer `yaml:"containers"`
	Shim       struct {
		UpstreamPort           int      `yaml:"upstream-port"`
		UpstreamContainer      string   `yaml:"upstream-container"`
		Authenticated          bool     `yaml:"authenticated"`
		AuthenticatedEndpoints []string `yaml:"authenticated-endpoints"`
		Paths                  []string `yaml:"paths"`
	} `yaml:"shim"`
}

type runtimeModel struct {
	Name string `yaml:"name"`
	Repo string `yaml:"repo"`
	MPK  string `yaml:"mpk"`
}

type runtimeContainer struct {
	Name        string              `yaml:"name"`
	Image       string              `yaml:"image"`
	Runtime     string              `yaml:"runtime"`
	GPUs        string              `yaml:"gpus"`
	Restart     string              `yaml:"restart"`
	Env         []map[string]string `yaml:"env"`
	Command     []string            `yaml:"command"`
	ReadOnly    *bool               `yaml:"read_only"`
	Tmpfs       map[string]string   `yaml:"tmpfs"`
	Healthcheck struct {
		Test        []string `yaml:"test"`
		Interval    string   `yaml:"interval"`
		Timeout     string   `yaml:"timeout"`
		StartPeriod string   `yaml:"start_period"`
	} `yaml:"healthcheck"`
}

type modelPack struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	VerityRoot string `json:"verityRoot"`
	HashOffset string `json:"hashOffset"`
	UUID       string `json:"uuid"`
	MountPath  string `json:"mountPath"`
}

type runtimeResult struct {
	Profile                    string      `json:"profile"`
	RuntimeConstraintsVerified bool        `json:"runtimeConstraintsVerified"`
	AuthenticatedRelease       bool        `json:"authenticatedRelease"`
	InferenceQualified         bool        `json:"inferenceQualified"`
	ConfigDigest               string      `json:"configDigest"`
	CVMTag                     string      `json:"cvmTag"`
	CPUs                       int         `json:"cpus"`
	MemoryMB                   int         `json:"memoryMB"`
	GPUs                       int         `json:"gpus"`
	ImageDigest                string      `json:"imageDigest"`
	ModelPacks                 []modelPack `json:"modelPacks"`
	CPUVerified                bool        `json:"cpuVerified"`
	GPUVerified                bool        `json:"gpuVerified"`
	FreshnessVerified          bool        `json:"freshnessVerified"`
	Repo                       string      `json:"repo,omitempty"`
	Tag                        string      `json:"tag,omitempty"`
	ReleaseCommit              string      `json:"releaseCommit,omitempty"`
	DeploymentDigest           string      `json:"deploymentDigest,omitempty"`
}

// Decode the same constrained, literal configuration semantics used by the
// measured Go guest. Do not expand aliases, merges, external env or new fields.
func inspectRuntimeConfig(raw []byte) (*runtimeResult, error) {
	reject := errors.New("TEE_RUNTIME_CONFIG_REJECTED")
	if len(raw) == 0 || len(raw) > 128*1024 {
		return nil, reject
	}
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(&document) != nil {
		return nil, reject
	}
	var trailing yaml.Node
	if decoder.Decode(&trailing) != io.EOF {
		return nil, reject
	}
	var visit func(*yaml.Node, int) bool
	visit = func(node *yaml.Node, depth int) bool {
		if depth > 32 || node.Kind == yaml.AliasNode || node.Anchor != "" {
			return false
		}
		if node.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for n := 0; n < len(node.Content); n += 2 {
				key := node.Content[n]
				if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" || seen[key.Value] {
					return false
				}
				seen[key.Value] = true
			}
		}
		for _, child := range node.Content {
			if !visit(child, depth+1) {
				return false
			}
		}
		return true
	}
	if !visit(&document, 0) {
		return nil, reject
	}
	var config runtimeConfig
	decoder = yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if decoder.Decode(&config) != nil || config.CPUs < 1 || config.Memory < 1024 || config.GPUs != 1 || len(config.Containers) != 1 || len(config.Models) != 2 || !stableTag.MatchString("v"+config.CVMVersion) {
		return nil, reject
	}
	container := config.Containers[0]
	prefix := "ghcr.io/" + codeRepo + "@sha256:"
	if container.Name != "gemma4-31b" || container.Runtime != "nvidia" || container.GPUs != "all" || container.Restart != "always" ||
		(container.ReadOnly != nil && !*container.ReadOnly) || !strings.HasPrefix(container.Image, prefix) || !digestPattern.MatchString(strings.TrimPrefix(container.Image, prefix)) {
		return nil, reject
	}
	// Unknown top-level/container fields already reject: networks, volumes,
	// devices, capabilities, namespace sharing, secrets, vault and entrypoints.
	if len(container.Tmpfs) != 2 || container.Tmpfs["/tmp"] != "size=512m,mode=1777,exec" || container.Tmpfs["/root"] != "size=2g,mode=0700,exec" {
		return nil, reject
	}
	seenEnv := map[string]bool{}
	for _, entry := range container.Env {
		if len(entry) != 1 {
			return nil, reject
		}
		for key, value := range entry {
			if seenEnv[key] {
				return nil, reject
			}
			seenEnv[key] = true
			switch {
			case key == "PYTORCH_CUDA_ALLOC_CONF":
				if value != "expandable_segments:True" {
					return nil, reject
				}
			case key == "VLLM_USE_V2_MODEL_RUNNER":
				if value != "0" {
					return nil, reject
				}
			case key == "VLLM_CC_PAGEABLE_H2D", key == "VLLM_CC_OUTPUT_WORKER", key == "VLLM_CC_SPEC_COUNT_FAST_PUBLICATION", key == "VLLM_CC_DECODE_METADATA_FASTPATH", key == "VLLM_CC_BLOCK_TABLE_DIRTY_UPDATE", key == "VLLM_DISABLE_STRUCTURED_OUTPUT_REGEX":
				if value != "0" && value != "1" {
					return nil, reject
				}
			default:
				return nil, reject
			}
		}
	}
	if !seenEnv["VLLM_USE_V2_MODEL_RUNNER"] {
		return nil, reject
	}
	packPattern := regexp.MustCompile(`^([a-f0-9]{64})_([1-9][0-9]*)_([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$`)
	packs := make([]modelPack, 0, 2)
	roots := map[string]bool{}
	for n, model := range config.Models {
		expectedName, expectedRepo := "gemma-4-31b", "google/gemma-4-31B-it"
		if n == 1 {
			expectedName = "gemma-4-31b-assistant"
			expectedRepo = "google/gemma-4-31B-it-assistant"
		}
		parts := strings.Split(model.Repo, "@")
		match := packPattern.FindStringSubmatch(model.MPK)
		if model.Name != expectedName || len(parts) != 2 || parts[0] != expectedRepo || !commitPattern.MatchString(parts[1]) || len(match) != 4 {
			return nil, reject
		}
		offset, err := strconv.ParseUint(match[2], 10, 64)
		if err != nil || offset%4096 != 0 || offset > 1<<50 || roots[match[1]] {
			return nil, reject
		}
		roots[match[1]] = true
		packs = append(packs, modelPack{Name: model.Name, Source: model.Repo, VerityRoot: match[1], HashOffset: match[2], UUID: match[3], MountPath: "/tinfoil/mpk/mpk-" + match[1]})
	}
	if len(container.Command) > 80 {
		return nil, reject
	}
	values := map[string]string{}
	boolFlags := map[string]bool{"--enable-auto-tool-choice": true, "--enable-prompt-tokens-details": true}
	for n := 0; n < len(container.Command); n++ {
		key := container.Command[n]
		if !strings.HasPrefix(key, "--") || strings.Contains(key, "=") {
			return nil, reject
		}
		if _, exists := values[key]; exists {
			return nil, reject
		}
		if boolFlags[key] {
			values[key] = "true"
			continue
		}
		n++
		if n >= len(container.Command) {
			return nil, reject
		}
		values[key] = container.Command[n]
	}
	fixed := map[string]string{
		"--model": packs[0].MountPath, "--tensor-parallel-size": "1", "--attention-backend": "TRITON_ATTN",
		"--served-model-name": "gemma4-31b", "--enable-auto-tool-choice": "true", "--enable-prompt-tokens-details": "true",
		"--tool-call-parser": "gemma4", "--reasoning-parser": "gemma4", "--chat-template": "examples/tool_chat_template_gemma4.jinja",
		"--scheduling-policy": "priority", "--allowed-media-domains": "disabled.invalid", "--limit-mm-per-prompt": "{\"video\":0}",
	}
	for key, expected := range fixed {
		if values[key] != expected {
			return nil, reject
		}
		delete(values, key)
	}
	utilization, err := strconv.ParseFloat(values["--gpu-memory-utilization"], 64)
	if err != nil || !(utilization > 0 && utilization <= 0.95) {
		return nil, reject
	}
	delete(values, "--gpu-memory-utilization")
	sequences, err := strconv.Atoi(values["--max-num-seqs"])
	if err != nil || sequences < 1 || sequences > 1024 {
		return nil, reject
	}
	delete(values, "--max-num-seqs")
	port, err := strconv.Atoi(values["--port"])
	if err != nil || port < 1024 || port > 65535 || port != config.Shim.UpstreamPort {
		return nil, reject
	}
	delete(values, "--port")
	var speculation struct {
		Method string `json:"method"`
		Model  string `json:"model"`
		Tokens int    `json:"num_speculative_tokens"`
	}
	if decodeOne([]byte(values["--speculative-config"]), &speculation) != nil || speculation.Method != "mtp" || speculation.Model != packs[1].MountPath || speculation.Tokens < 1 || speculation.Tokens > 16 {
		return nil, reject
	}
	delete(values, "--speculative-config")
	if len(values) != 0 {
		return nil, reject
	}
	if !config.Shim.Authenticated || (config.Shim.UpstreamContainer != "" && config.Shim.UpstreamContainer != container.Name) {
		return nil, reject
	}
	allowedPaths := map[string]bool{"/v1/chat/completions": true, "/v1/models": true, "/v1/responses": true, "/tokenize": true, "/metrics": true, "/health": true}
	paths := map[string]bool{}
	for _, path := range config.Shim.Paths {
		if !allowedPaths[path] || paths[path] {
			return nil, reject
		}
		paths[path] = true
	}
	if !paths["/v1/chat/completions"] {
		return nil, reject
	}
	authenticated := map[string]bool{}
	for _, path := range config.Shim.AuthenticatedEndpoints {
		if !paths[path] || authenticated[path] {
			return nil, reject
		}
		authenticated[path] = true
	}
	if !authenticated["/v1/chat/completions"] || (paths["/metrics"] && !authenticated["/metrics"]) {
		return nil, reject
	}
	health := []string{"CMD", "curl", "-sf", fmt.Sprintf("http://localhost:%d/health", port)}
	if !slices.Equal(container.Healthcheck.Test, health) {
		return nil, reject
	}
	return &runtimeResult{Profile: runtimeProfile, RuntimeConstraintsVerified: true, ConfigDigest: digest256(raw), CVMTag: "v" + config.CVMVersion,
		CPUs: config.CPUs, MemoryMB: config.Memory, GPUs: 1, ImageDigest: strings.TrimPrefix(container.Image, prefix), ModelPacks: packs}, nil
}

func runRuntimeInspection(reader io.Reader, writer io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	var input struct {
		Config string `json:"config"`
	}
	var checked *runtimeResult
	if err == nil && len(raw) <= maxInputBytes && decodeOne(raw, &input) == nil {
		config, decoded := bytes64(input.Config)
		if decoded == nil {
			checked, err = inspectRuntimeConfig(config)
		} else {
			err = decoded
		}
	} else {
		err = errors.New("input")
	}
	if err != nil {
		json.NewEncoder(writer).Encode(map[string]any{"runtimeConstraintsVerified": false, "authenticatedRelease": false, "inferenceQualified": false, "failure": "TEE_RUNTIME_CONFIG_REJECTED"})
		return 1
	}
	if json.NewEncoder(writer).Encode(checked) != nil {
		return 1
	}
	return 0
}

func runRuntimeRelease(reader io.Reader, writer io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	var input containerReferenceInput
	var checked *runtimeResult
	if err == nil && len(raw) <= maxInputBytes && decodeOne(raw, &input) == nil {
		checked, err = authenticateRuntimeRelease(&input)
	} else {
		err = errors.New("input")
	}
	if err != nil {
		json.NewEncoder(writer).Encode(map[string]any{"runtimeConstraintsVerified": false, "authenticatedRelease": false, "inferenceQualified": false, "failure": "TEE_RUNTIME_CONFIG_REJECTED"})
		return 1
	}
	if json.NewEncoder(writer).Encode(checked) != nil {
		return 1
	}
	return 0
}

func authenticateRuntimeRelease(input *containerReferenceInput) (*runtimeResult, error) {
	reject := errors.New("TEE_RUNTIME_CONFIG_REJECTED")
	code, imageDigest, err := authenticatedContainerReference(input.Tag, input.Deployment, input.Bundle)
	if err != nil {
		return nil, reject
	}
	deployment, err := bytes64(input.Deployment)
	if err != nil {
		return nil, reject
	}
	var release struct {
		Config  string `json:"config"`
		Command string `json:"cmdline"`
		Hashes  struct {
			Version string `json:"version"`
			Root    string `json:"root"`
		} `json:"hashes"`
	}
	if json.Unmarshal(deployment, &release) != nil {
		return nil, reject
	}
	config, err := bytes64(release.Config)
	if err != nil {
		return nil, reject
	}
	checked, err := inspectRuntimeConfig(config)
	if err != nil || checked.ImageDigest != imageDigest || checked.CVMTag != release.Hashes.Version || !digestPattern.MatchString(release.Hashes.Root) {
		return nil, reject
	}
	shape := code.Shape
	if shape == nil || shape.CPUs != checked.CPUs || shape.MemoryMB != checked.MemoryMB || shape.GPUs == nil || *shape.GPUs != checked.GPUs || shape.Disks != 3+len(checked.ModelPacks) {
		return nil, reject
	}
	expectedCommand := "readonly=on pci=realloc,nocrs modprobe.blacklist=nouveau nouveau.modeset=0 root=/dev/mapper/root roothash=" + release.Hashes.Root + " tinfoil-config-hash=" + checked.ConfigDigest
	if release.Command != expectedCommand {
		return nil, reject
	}
	checked.AuthenticatedRelease = true
	checked.Repo, checked.Tag, checked.ReleaseCommit, checked.DeploymentDigest = code.Repo, code.Tag, code.Commit, code.Digest
	return checked, nil
}
