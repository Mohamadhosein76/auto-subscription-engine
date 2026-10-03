"""Stage 1 CI safety contract."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _ci_text() -> str:
    return CI.read_text(encoding="utf-8")


def _ci() -> dict:
    return yaml.safe_load(_ci_text())


def test_ci_runs_on_push_and_pull_request():
    parsed = _ci()
    triggers = parsed[True] if True in parsed else parsed["on"]
    assert "push" in triggers
    assert "pull_request" in triggers


def test_ci_is_read_only_and_bounded():
    parsed = _ci()
    assert parsed["permissions"] == {"contents": "read"}
    job = parsed["jobs"]["test"]
    assert job["timeout-minutes"] <= 15


def test_ci_runs_regression_compile_and_public_contract():
    text = _ci_text()
    assert "python -m compileall -q src" in text
    assert "python -m pytest -q" in text
    assert "verify-publish --public-dir public" in text


def test_ci_never_pushes_or_uses_secrets():
    text = _ci_text()
    assert "git push" not in text
    assert "secrets." not in text
    assert "github_pat_" not in text
