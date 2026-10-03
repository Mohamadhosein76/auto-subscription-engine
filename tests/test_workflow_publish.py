"""Task 3 tests: workflow-level publish/schedule/security invariants.

These tests parse the committed workflow YAML and assert the structural
contract of the automation: hourly schedule, least-privilege permissions,
concurrency protection, guarded transactional publish, bounded fast-forward
auto-commit (never force), and no credential handling anywhere.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "build-subscription.yml"


def _workflow_text() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def _workflow() -> dict:
    return yaml.safe_load(_workflow_text())


def test_workflow_file_exists():
    assert WORKFLOW_PATH.is_file()


def test_schedule_and_manual_trigger_present():
    triggers = _workflow()[True] if True in _workflow() else _workflow()["on"]
    assert "workflow_dispatch" in triggers
    schedules = triggers["schedule"]
    crons = [entry["cron"] for entry in schedules]
    assert crons == ["17 * * * *"], "expected the hourly off-peak cron schedule"


def test_cron_is_not_on_the_hour():
    triggers = _workflow()[True] if True in _workflow() else _workflow()["on"]
    cron = triggers["schedule"][0]["cron"]
    minute = int(cron.split()[0])
    assert minute != 0, "use an off-peak minute to reduce scheduler congestion"


def test_permissions_are_least_privilege():
    permissions = _workflow()["permissions"]
    assert permissions == {"contents": "write"}


def test_concurrency_protection():
    concurrency = _workflow()["concurrency"]
    assert concurrency["group"] == "auto-subscription-publish"
    assert concurrency["cancel-in-progress"] is False


def test_job_timeout_is_bounded():
    job = _workflow()["jobs"]["build"]
    assert isinstance(job["timeout-minutes"], int)
    assert job["timeout-minutes"] <= 60


def test_no_force_push_anywhere():
    text = _workflow_text()
    assert "--force" not in text
    assert "push -f" not in text
    assert "git push --force" not in text


def test_push_is_bounded_retry_with_rebase_not_force():
    text = _workflow_text()
    assert "for attempt in 1 2 3" in text
    assert "git rebase origin/main" in text
    assert "git rebase --abort" in text


def test_no_empty_commit_guard_present():
    text = _workflow_text()
    assert "git diff --cached --quiet" in text


def test_auto_commit_uses_bot_identity():
    text = _workflow_text()
    assert 'user.name "github-actions[bot]"' in text
    assert "users.noreply.github.com" in text


def test_workflow_has_no_pat_and_never_prints_token():
    text = _workflow_text()
    assert "github_pat_" not in text
    assert "secrets." not in text, "workflow must rely on the default GITHUB_TOKEN only"
    # the token may only appear inside the checkout input, never echoed
    assert "github.token" in text
    for line in text.splitlines():
        stripped = line.strip()
        if "github.token" in stripped:
            assert stripped.startswith("token:"), f"token used outside checkout: {stripped}"


def test_publish_step_chain_present():
    text = _workflow_text()
    assert "auto_subscription_engine publish" in text
    assert "auto_subscription_engine verify-publish" in text
    assert "auto_subscription_engine verify-live" in text
    assert "Enforce publish guard status" in text


def test_history_baseline_snapshot_before_pipeline():
    text = _workflow_text()
    snapshot_pos = text.find("history-baseline.json")
    pipeline_pos = text.find("Run real connectivity pipeline")
    assert 0 < snapshot_pos < pipeline_pos, (
        "history baseline must be snapshotted before the live pipeline runs"
    )


def test_artifacts_uploaded_even_on_failure():
    text = _workflow_text()
    assert text.count("if: always()") >= 2
    assert "output/live_diagnostics.json" in text
    assert "output/publish_decision.json" in text


def test_workflow_uses_standard_checkout_token_not_custom_secret():
    text = _workflow_text()
    assert "${{ github.token }}" in text
    assert "persist-credentials: true" in text
    assert "fetch-depth: 0" in text
