package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mohamadhosein76/auto-subscription-engine/operator-probe-agent/internal/envelope"
	"github.com/Mohamadhosein76/auto-subscription-engine/operator-probe-agent/internal/runner"
)

const version = "stage8-1"

func main() {
	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: ase-operator-probe run [options]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	jobPath := fs.String("job", "", "signed probe-job envelope")
	outputPath := fs.String("output", "", "signed result envelope")
	python := fs.String("python", "python3", "python interpreter")
	coreDir := fs.String("core-dir", ".core-bin", "checksum-verified core directory")
	testingConfig := fs.String("testing-config", "config/testing.yaml", "testing policy config")
	probeID := fs.String("probe-id", "", "stable non-secret probe identifier")
	operatorProfile := fs.String("operator-profile", "", "operator profile key")
	secretEnv := fs.String("secret-env", "ASE_OPERATOR_PROBE_SECRET", "environment variable containing HMAC secret")
	keyID := fs.String("key-id", "", "result signing key id")
	_ = fs.Parse(os.Args[2:])

	if *jobPath == "" || *outputPath == "" || *probeID == "" || *operatorProfile == "" {
		fmt.Fprintln(os.Stderr, "job, output, probe-id and operator-profile are required")
		os.Exit(2)
	}
	secret := os.Getenv(*secretEnv)
	if secret == "" {
		fmt.Fprintf(os.Stderr, "%s is empty\n", *secretEnv)
		os.Exit(2)
	}
	jobEnvelope, err := os.ReadFile(*jobPath)
	if err != nil {
		fatal(err)
	}
	_, rawJob, err := envelope.Verify(jobEnvelope, "probe_job", secret)
	if err != nil {
		fatal(err)
	}
	var jobPayload map[string]any
	if err := json.Unmarshal(rawJob, &jobPayload); err != nil {
		fatal(fmt.Errorf("job payload is invalid JSON: %w", err))
	}
	if fmt.Sprint(jobPayload["operator_profile"]) != *operatorProfile {
		fatal(fmt.Errorf("job operator profile mismatch"))
	}

	tmpDir, err := os.MkdirTemp("", "ase-operator-probe-")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	decodedJob := filepath.Join(tmpDir, "job.json")
	workerOutput := filepath.Join(tmpDir, "result.json")
	if err := os.WriteFile(decodedJob, rawJob, 0600); err != nil {
		fatal(err)
	}
	if err := runner.RunWorker(runner.Options{
		Python: *python, JobPath: decodedJob, OutputPath: workerOutput,
		CoreDir: *coreDir, TestingConfig: *testingConfig, ProbeID: *probeID,
		OperatorProfile: *operatorProfile,
	}); err != nil {
		fatal(err)
	}
	rawResult, err := os.ReadFile(workerOutput)
	if err != nil {
		fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rawResult, &payload); err != nil {
		fatal(fmt.Errorf("worker result is invalid JSON: %w", err))
	}
	if fmt.Sprint(payload["job_id"]) != fmt.Sprint(jobPayload["job_id"]) {
		fatal(fmt.Errorf("worker result job_id mismatch"))
	}
	if containsSensitive(payload) {
		fatal(fmt.Errorf("worker result contains sensitive fields"))
	}
	payload["agent_binary_version"] = version
	payload["operator_profile"] = *operatorProfile
	payload["probe_id"] = *probeID
	rawResult, err = json.Marshal(payload)
	if err != nil {
		fatal(err)
	}
	kid := *keyID
	if kid == "" {
		kid = *probeID
	}
	resultEnvelope, err := envelope.Sign(rawResult, "probe_result", kid, secret)
	if err != nil {
		fatal(err)
	}
	encoded, err := json.MarshalIndent(resultEnvelope, "", "  ")
	if err != nil {
		fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*outputPath, encoded, 0600); err != nil {
		fatal(err)
	}
}

func containsSensitive(value any) bool {
	sensitive := map[string]bool{"uri": true, "original_uri": true, "password": true, "uuid": true, "token": true, "secret": true}
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if sensitive[strings.ToLower(key)] || containsSensitive(child) {
				return true
			}
		}
	case []any:
		for _, child := range item {
			if containsSensitive(child) {
				return true
			}
		}
	case string:
		return strings.Contains(item, "://")
	}
	return false
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
