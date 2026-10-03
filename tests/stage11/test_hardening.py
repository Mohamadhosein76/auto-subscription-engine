from __future__ import annotations

import json
from pathlib import Path

import pytest

from auto_subscription_engine.core.hardening.publication import recover_publish_transaction
from auto_subscription_engine.core.hardening.state import (
    StateCorruptionError,
    atomic_write_json,
    backup_path,
    load_json_state,
)
from auto_subscription_engine.core.discovery import SourceIntelligenceStore
from auto_subscription_engine.core.network import DnsHistoryStore
from auto_subscription_engine.core.operator_probe.store import OperatorProbeStore


def test_atomic_state_write_keeps_last_known_good_backup(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    atomic_write_json(path, {"version": 1})
    atomic_write_json(path, {"version": 2})
    assert json.loads(path.read_text()) == {"version": 2}
    assert json.loads(backup_path(path).read_text()) == {"version": 1}


def test_state_loader_recovers_corrupt_primary_from_backup(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    atomic_write_json(path, {"version": 1})
    atomic_write_json(path, {"version": 2})
    path.write_text("{truncated", encoding="utf-8")
    assert load_json_state(path) == {"version": 1}
    assert json.loads(path.read_text()) == {"version": 1}


def test_state_loader_fails_closed_when_primary_and_backup_are_corrupt(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{bad", encoding="utf-8")
    backup_path(path).write_text("{also-bad", encoding="utf-8")
    with pytest.raises(StateCorruptionError):
        load_json_state(path)


def test_discovery_existing_corrupt_state_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "discovery.json"
    path.write_text("{bad", encoding="utf-8")
    with pytest.raises(StateCorruptionError):
        SourceIntelligenceStore.load(path)


def test_dns_existing_corrupt_state_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "ip_history.json"
    path.write_text("{bad", encoding="utf-8")
    with pytest.raises(StateCorruptionError):
        DnsHistoryStore.load(path)


def test_operator_existing_corrupt_state_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "operator_probes.json"
    path.write_text("{bad", encoding="utf-8")
    with pytest.raises(StateCorruptionError):
        OperatorProbeStore(path)


def test_publish_recovery_restores_previous_tree_after_interrupted_swap(tmp_path: Path) -> None:
    public = tmp_path / "public"
    staging = tmp_path / "public.staging"
    backup = tmp_path / ".public.old-123"
    backup.mkdir()
    (backup / "marker.txt").write_text("previous-good", encoding="utf-8")
    staging.mkdir()
    (staging / "marker.txt").write_text("untrusted-stale-stage", encoding="utf-8")

    actions = recover_publish_transaction(public, staging)

    assert (public / "marker.txt").read_text() == "previous-good"
    assert not staging.exists()
    assert not backup.exists()
    assert "restored_previous_public" in actions


def test_publish_recovery_discards_stale_stage_when_public_is_healthy(tmp_path: Path) -> None:
    public = tmp_path / "public"
    staging = tmp_path / "public.staging"
    backup = tmp_path / ".public.old-456"
    public.mkdir()
    (public / "marker.txt").write_text("current-good", encoding="utf-8")
    staging.mkdir()
    backup.mkdir()

    recover_publish_transaction(public, staging)

    assert (public / "marker.txt").read_text() == "current-good"
    assert not staging.exists()
    assert not backup.exists()


def test_release_gate_passes_clean_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess
    import auto_subscription_engine.core.hardening.release as release

    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "testing.yaml").write_text("x: 1\n", encoding="utf-8")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")
    (tmp_path / "data").mkdir()
    for name, payload in {
        "history.json": {"schema_version": 4, "entries": {}},
        "discovery.json": {"schema_version": 1, "sources": {}},
        "ip_history.json": {"schema_version": 1, "hosts": {}},
        "operator_probes.json": {"schema_version": 1, "nodes": {}, "processed_result_ids": []},
    }.items():
        (tmp_path / "data" / name).write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "output").mkdir()
    (tmp_path / "output" / "scorecards.json").write_text("[]", encoding="utf-8")
    (tmp_path / "output" / "feed_manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "public").mkdir()

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "config", ".github", "data"], cwd=tmp_path, check=True)

    monkeypatch.setattr(release, "verify_public_dir", lambda _path: [])
    monkeypatch.setattr(release, "verify_scoring_outputs", lambda _path: [])
    monkeypatch.setattr(release, "verify_feed_outputs", lambda _path: [])

    report = release.run_release_gate(
        repo_root=tmp_path,
        output_dir=Path("output"),
        public_dir=Path("public"),
    )
    assert report.passed
    assert all(item.passed for item in report.checks)


def test_release_gate_rejects_sensitive_material_in_state(tmp_path: Path) -> None:
    from auto_subscription_engine.core.hardening.release import _state_problems

    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "history.json").write_text(
        json.dumps({"entries": {}, "note": "vless://secret@example.com:443"}),
        encoding="utf-8",
    )
    problems = _state_problems(tmp_path, 1024 * 1024)
    assert any("sensitive proxy material" in item for item in problems)


def test_stage11_workflow_release_gate_precedes_commit() -> None:
    root = Path(__file__).resolve().parents[2]
    text = (root / ".github" / "workflows" / "build-subscription.yml").read_text(encoding="utf-8")
    gate = text.index("Production release gate")
    commit = text.index("Auto-commit published subscription and history")
    assert gate < commit
    assert "production_health.json" in text


def test_operator_workflow_has_bounded_push_and_cleanup() -> None:
    root = Path(__file__).resolve().parents[2]
    text = (root / ".github" / "workflows" / "operator-probe.yml").read_text(encoding="utf-8")
    assert "for attempt in 1 2 3" in text
    assert "git rebase --abort" in text
    assert "group: operator-probe-state" in text
    assert "timeout-minutes: 45" in text
    assert "Cleanup probe credentials and runtime binaries" in text
    assert 'rm -f "$RUNNER_TEMP/operator-job.json"' in text


def test_production_check_cli_is_registered() -> None:
    from auto_subscription_engine.cli import build_parser

    args = build_parser().parse_args(["production-check"])
    assert args.command == "production-check"
    assert args.output_dir == Path("output")
    assert args.public_dir == Path("public")
    assert args.report == Path("output/production_health.json")
