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

const runtimeProfile = "tinfoil-vllm-v1"

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
	// Declarative pack layout version; tinfoil-config v0.1.8 has no consumer.
	// Executable, wrapped and encrypted packs are unknown fields and reject.
	Schema int `yaml:"schema"`
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
	CodeStatementDigest        string      `json:"codeStatementDigest,omitempty"`
	SubjectPredicateMatched    bool        `json:"subjectPredicateMatched"`
}

// Accept a strict subset of the guest's configuration language. Inherited
// environment strings, aliases, merges and unsupported fields are rejected.
func inspectRuntimeConfig(raw []byte, codeRepo string) (*runtimeResult, error) {
	served := publicRepos[codeRepo]
	reject := errors.New("TEE_RUNTIME_CONFIG_REJECTED")
	if served == "" || len(raw) == 0 || len(raw) > 128*1024 {
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
	// Unknown top-level/container fields reject: networks, volumes, devices,
	// capabilities, namespace sharing, secrets, vault and entrypoints.
	if decoder.Decode(&config) != nil || config.CPUs < 1 || config.Memory < 1024 || config.GPUs < 1 || config.GPUs > 8 ||
		len(config.Containers) != 1 || len(config.Models) < 1 || len(config.Models) > 4 || !stableTag.MatchString("v"+config.CVMVersion) {
		return nil, reject
	}
	container := config.Containers[0]
	prefix := "ghcr.io/" + codeRepo + "@sha256:"
	if !containerName.MatchString(container.Name) || container.Runtime != "nvidia" || container.GPUs != "all" || container.Restart != "always" ||
		(container.ReadOnly != nil && !*container.ReadOnly) || !strings.HasPrefix(container.Image, prefix) || !digestPattern.MatchString(strings.TrimPrefix(container.Image, prefix)) {
		return nil, reject
	}
	// Only RAM-backed scratch space at the engine's two writable paths.
	tmpfsOptions := regexp.MustCompile(`^size=[1-9][0-9]{0,4}[mg],mode=(1777|0700),exec$`)
	if len(container.Tmpfs) != 2 || !tmpfsOptions.MatchString(container.Tmpfs["/tmp"]) || !tmpfsOptions.MatchString(container.Tmpfs["/root"]) {
		return nil, reject
	}
	seenEnv := map[string]bool{}
	bit := func(value string) bool { return value == "0" || value == "1" }
	count := func(value string) bool { return regexp.MustCompile(`^[1-9][0-9]{0,11}$`).MatchString(value) }
	for _, entry := range container.Env {
		if len(entry) != 1 {
			return nil, reject
		}
		for key, value := range entry {
			if seenEnv[key] {
				return nil, reject
			}
			seenEnv[key] = true
			ok := false
			switch key {
			case "PYTORCH_CUDA_ALLOC_CONF":
				ok = value == "expandable_segments:True"
			case "VLLM_USE_V2_MODEL_RUNNER", "VLLM_CC_PAGEABLE_H2D", "VLLM_CC_OUTPUT_WORKER", "VLLM_CC_SPEC_COUNT_FAST_PUBLICATION",
				"VLLM_CC_DECODE_METADATA_FASTPATH", "VLLM_CC_BLOCK_TABLE_DIRTY_UPDATE", "VLLM_DISABLE_STRUCTURED_OUTPUT_REGEX",
				"VLLM_ALLREDUCE_USE_SYMM_MEM", "VLLM_ALLREDUCE_USE_FLASHINFER":
				ok = bit(value)
			case "FLASHINFER_NO_DOWNLOAD":
				ok = value == "1"
			case "NUMBA_CACHE_DIR":
				ok = value == "/root/numba-cache"
			case "VLLM_ENGINE_READY_TIMEOUT_S", "RUNAI_STREAMER_MEMORY_LIMIT", "RUNAI_STREAMER_CONCURRENCY":
				ok = count(value)
			}
			if !ok {
				return nil, reject
			}
		}
	}
	packPattern := regexp.MustCompile(`^([a-f0-9]{64})_([1-9][0-9]*)_([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$`)
	modelName := regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	modelRepo := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
	packs := make([]modelPack, 0, len(config.Models))
	roots, mounts := map[string]bool{}, map[string]bool{}
	for _, model := range config.Models {
		parts := strings.Split(model.Repo, "@")
		match := packPattern.FindStringSubmatch(model.MPK)
		if model.Schema < 0 || model.Schema > 2 || !modelName.MatchString(model.Name) || len(parts) != 2 || !modelRepo.MatchString(parts[0]) || !commitPattern.MatchString(parts[1]) || len(match) != 4 {
			return nil, reject
		}
		offset, err := strconv.ParseUint(match[2], 10, 64)
		if err != nil || offset%4096 != 0 || offset > 1<<50 || roots[match[1]] {
			return nil, reject
		}
		roots[match[1]] = true
		mount := "/tinfoil/mpk/mpk-" + match[1]
		mounts[mount] = true
		packs = append(packs, modelPack{Name: model.Name, Source: model.Repo, VerityRoot: match[1], HashOffset: match[2], UUID: match[3], MountPath: mount})
	}
	if len(container.Command) > 96 {
		return nil, reject
	}
	values := map[string]string{}
	boolFlags := map[string]bool{
		"--enable-auto-tool-choice": true, "--enable-prompt-tokens-details": true, "--enable-force-include-usage": true,
		"--disable-custom-all-reduce": true, "--enable-expert-parallel": true, "--enable-prefix-caching": true, "--no-enable-flashinfer-autotune": true,
	}
	for n := 0; n < len(container.Command); n++ {
		key, inline, hasInline := strings.Cut(container.Command[n], "=")
		if !strings.HasPrefix(key, "--") {
			return nil, reject
		}
		if _, exists := values[key]; exists {
			return nil, reject
		}
		if boolFlags[key] {
			if hasInline {
				return nil, reject
			}
			values[key] = "true"
			continue
		}
		if hasInline {
			values[key] = inline
			continue
		}
		n++
		if n >= len(container.Command) {
			return nil, reject
		}
		values[key] = container.Command[n]
	}
	identifier := regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	number := func(value string, low, high float64) bool {
		parsed, err := strconv.ParseFloat(value, 64)
		return err == nil && parsed >= low && parsed <= high
	}
	integer := func(value string, low, high int) bool {
		parsed, err := strconv.Atoi(value)
		return err == nil && strconv.Itoa(parsed) == value && parsed >= low && parsed <= high
	}
	port, err := strconv.Atoi(values["--port"])
	if err != nil || port < 1024 || port > 65535 || port != config.Shim.UpstreamPort {
		return nil, reject
	}
	// Each accepted flag has a value check; any other flag rejects, including
	// request logging, remote code, adapters, downloads and media fetching.
	checks := map[string]func(string) bool{
		"--model":                  func(v string) bool { return v == packs[0].MountPath },
		"--served-model-name":      func(v string) bool { return v == served },
		"--port":                   func(string) bool { return true },
		"--tensor-parallel-size":   func(v string) bool { return v == strconv.Itoa(config.GPUs) },
		"--gpu-memory-utilization": func(v string) bool { return number(v, 0.01, 0.95) },
		"--max-num-seqs":           func(v string) bool { return integer(v, 1, 1024) },
		"--max-model-len":          func(v string) bool { return integer(v, 1, 1<<24) },
		"--kv-cache-dtype":         func(v string) bool { return v == "auto" || v == "fp8" || v == "fp8_e4m3" || v == "fp8_e5m2" },
		"--attention-backend":      func(v string) bool { return identifier.MatchString(v) },
		"--tool-call-parser":       func(v string) bool { return identifier.MatchString(v) },
		"--reasoning-parser":       func(v string) bool { return identifier.MatchString(v) },
		"--tokenizer-mode":         func(v string) bool { return identifier.MatchString(v) },
		"--chat-template": func(v string) bool {
			return regexp.MustCompile(`^examples/[A-Za-z0-9_.-]{1,96}\.jinja$`).MatchString(v)
		},
		"--chat-template-content-format": func(v string) bool { return v == "string" || v == "openai" },
		"--scheduling-policy":            func(v string) bool { return v == "priority" || v == "fcfs" },
		"--allowed-media-domains":        func(v string) bool { return v == "disabled.invalid" },
		"--limit-mm-per-prompt": func(v string) bool {
			return jsonObject(v, func(_ string, value any) bool { n, ok := value.(float64); return ok && n >= 0 && n <= 64 })
		},
		"--load-format":        func(v string) bool { return v == "auto" || v == "safetensors" || v == "runai_streamer" },
		"--mm-encoder-tp-mode": func(v string) bool { return v == "data" || v == "weights" },
		"--mamba-cache-mode":   func(v string) bool { return identifier.MatchString(v) },
		"--middleware":         func(v string) bool { return v == "tinfoil_usage.UsageMetricsMiddleware" },
		"--compilation-config": func(v string) bool { return jsonObject(v, compilationSetting) },
		"--engram-config": func(v string) bool {
			return jsonObject(v, func(key string, value any) bool { _, ok := value.(bool); return key == "cpu_offload" && ok })
		},
		"--attention-config":              func(v string) bool { return jsonObject(v, func(_ string, value any) bool { return scalar(value) }) },
		"--override-generation-config":    func(v string) bool { return jsonObject(v, generationSetting) },
		"--speculative-config":            func(v string) bool { return speculativeSetting(v, mounts) },
		"--enable-auto-tool-choice":       func(string) bool { return true },
		"--enable-prompt-tokens-details":  func(string) bool { return true },
		"--enable-force-include-usage":    func(string) bool { return true },
		"--disable-custom-all-reduce":     func(string) bool { return true },
		"--enable-expert-parallel":        func(string) bool { return true },
		"--enable-prefix-caching":         func(string) bool { return true },
		"--no-enable-flashinfer-autotune": func(string) bool { return true },
	}
	for _, required := range []string{"--model", "--served-model-name", "--port"} {
		if _, ok := values[required]; !ok {
			return nil, reject
		}
	}
	if config.GPUs > 1 {
		if _, ok := values["--tensor-parallel-size"]; !ok {
			return nil, reject
		}
	}
	for key, value := range values {
		check, ok := checks[key]
		if !ok || !check(value) {
			return nil, reject
		}
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
		CPUs: config.CPUs, MemoryMB: config.Memory, GPUs: config.GPUs, ImageDigest: strings.TrimPrefix(container.Image, prefix), ModelPacks: packs}, nil
}

func scalar(value any) bool {
	switch typed := value.(type) {
	case bool, float64:
		return true
	case string:
		return regexp.MustCompile(`^[A-Za-z0-9_.-]{0,64}$`).MatchString(typed)
	}
	return false
}

// A JSON object with bounded keys whose every member passes check.
func jsonObject(raw string, check func(string, any) bool) bool {
	var object map[string]any
	if len(raw) > 4096 || decodeOne([]byte(raw), &object) != nil || len(object) > 32 {
		return false
	}
	for key, value := range object {
		if !regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`).MatchString(key) || !check(key, value) {
			return false
		}
	}
	return true
}

func compilationSetting(key string, value any) bool {
	switch key {
	case "mode", "level":
		n, ok := value.(float64)
		return ok && n >= 0 && n <= 3 && n == float64(int(n))
	case "cudagraph_mode":
		s, ok := value.(string)
		return ok && regexp.MustCompile(`^[A-Z_]{1,32}$`).MatchString(s)
	case "pass_config":
		passes, ok := value.(map[string]any)
		if !ok || len(passes) > 16 {
			return false
		}
		for name, enabled := range passes {
			if _, isBool := enabled.(bool); !isBool || !regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`).MatchString(name) {
				return false
			}
		}
		return true
	}
	return false
}

func generationSetting(key string, value any) bool {
	n, ok := value.(float64)
	switch key {
	case "temperature":
		return ok && n >= 0 && n <= 2
	case "top_p":
		return ok && n > 0 && n <= 1
	case "top_k":
		return ok && n >= -1 && n <= 1000 && n == float64(int(n))
	case "max_new_tokens":
		return ok && n >= 1 && n <= 1<<24 && n == float64(int(n))
	}
	return false
}

// Speculative decoding may use a draft model only from an authenticated pack.
func speculativeSetting(raw string, mounts map[string]bool) bool {
	return jsonObject(raw, func(key string, value any) bool {
		switch key {
		case "method":
			s, ok := value.(string)
			return ok && (s == "mtp" || s == "dspark" || s == "eagle" || s == "eagle3")
		case "model":
			s, ok := value.(string)
			return ok && mounts[s]
		case "num_speculative_tokens":
			n, ok := value.(float64)
			return ok && n >= 1 && n <= 16 && n == float64(int(n))
		case "draft_sample_method", "rejection_sample_method":
			s, ok := value.(string)
			return ok && regexp.MustCompile(`^[a-z_]{1,32}$`).MatchString(s)
		case "enable_adaptive_verification":
			_, ok := value.(bool)
			return ok
		}
		return false
	})
}

func runRuntimeInspection(reader io.Reader, writer io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	var input struct {
		Repo   string `json:"repo"`
		Config string `json:"config"`
	}
	var checked *runtimeResult
	if err == nil && len(raw) <= maxInputBytes && decodeOne(raw, &input) == nil {
		config, decoded := bytes64(input.Config)
		if decoded == nil {
			checked, err = inspectRuntimeConfig(config, input.Repo)
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
	code, imageDigest, err := authenticatedContainerReference(input.Repo, input.Tag, input.Deployment, input.Bundle)
	if err != nil {
		return nil, reject
	}
	deploymentRaw, err := bytes64(input.Deployment)
	if err != nil {
		return nil, reject
	}
	var release deployment
	if decodeOne(deploymentRaw, &release) != nil {
		return nil, reject
	}
	config, err := bytes64(release.Config)
	if err != nil {
		return nil, reject
	}
	checked, err := inspectRuntimeConfig(config, input.Repo)
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
	_, statementDigest, err := codePredicate(input.Bundle, code)
	if err != nil {
		return nil, reject
	}
	checked.SubjectPredicateMatched, checked.CodeStatementDigest = true, statementDigest
	return checked, nil
}
