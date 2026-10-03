from __future__ import annotations

from pathlib import Path


def test_operator_probe_code_is_centralized():
    root = Path("src/auto_subscription_engine/core/operator_probe")
    assert (root / "worker.py").is_file()
    assert (root / "agent" / "go.mod").is_file()
    assert (root / "agent" / "cmd" / "ase-operator-probe" / "main.go").is_file()
    assert not Path("src/auto_subscription_engine/operator_probe.py").exists()
    assert not Path("operator_probe").exists()


def test_operator_workflow_is_self_hosted_manual_and_secret_safe():
    text = Path(".github/workflows/operator-probe.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch" in text
    assert "runs-on: [self-hosted" in text
    assert "secrets.ASE_OPERATOR_PROBE_SECRET" in text
    assert "operator-${{ inputs.operator_profile }}" in text
    assert "operator-probe-job" in text
    assert "operator-probe-ingest" in text
    assert "upload-artifact" not in text  # signed job contains proxy credentials
    assert "github_pat_" not in text


def test_ci_runs_go_agent_tests():
    text = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "actions/setup-go@v5" in text
    assert "core/operator_probe/agent" in text
    assert "go test ./..." in text
