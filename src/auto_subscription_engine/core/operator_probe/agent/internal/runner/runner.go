package runner

import (
	"bytes"
	"fmt"
	"os/exec"
)

type Options struct {
	Python          string
	JobPath         string
	OutputPath      string
	CoreDir         string
	TestingConfig   string
	ProbeID         string
	OperatorProfile string
}

func RunWorker(opts Options) error {
	python := opts.Python
	if python == "" {
		python = "python3"
	}
	args := []string{
		"-m", "auto_subscription_engine.core.operator_probe.worker",
		"--job", opts.JobPath,
		"--output", opts.OutputPath,
		"--core-dir", opts.CoreDir,
		"--testing-config", opts.TestingConfig,
		"--probe-id", opts.ProbeID,
		"--operator-profile", opts.OperatorProfile,
	}
	cmd := exec.Command(python, args...)
	var stderr bytes.Buffer
	cmd.Stdout = nil
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("operator worker failed: %w: %s", err, stderr.String())
	}
	return nil
}
