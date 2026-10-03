"""Tests for the command-line interface (run / verify)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auto_subscription_engine import cli as cli_mod
import auto_subscription_engine.core.discovery.engine as discovery_engine_mod
from auto_subscription_engine.cli import main
from auto_subscription_engine.core.discovery import FetchOutcome

FIXTURES = Path(__file__).parent / "fixtures"


def test_run_offline(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_dir = tmp_path / "out"
    code = main(
        [
            "run",
            "--from-file",
            str(FIXTURES / "mixed_subscription.txt"),
            "--output-dir",
            str(output_dir),
        ]
    )
    assert code == 0
    assert (output_dir / "subscription.txt").is_file()
    assert (output_dir / "subscription_base64.txt").is_file()
    assert (output_dir / "stats.json").is_file()

    captured = capsys.readouterr()
    assert "final configs: 6" in captured.out
    # Sensitive config contents must never be printed.
    assert "vless://" not in captured.out


def test_no_arguments_defaults_to_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: dict[str, object] = {}

    def fake_run_pipeline(options):
        calls["options"] = options
        return {
            "sources_total": 1,
            "sources_success": 1,
            "sources_failed": 0,
            "configs_received": 0,
            "configs_valid": 0,
            "configs_invalid": 0,
            "configs_unknown_protocol": 0,
            "duplicates_removed": 0,
            "final_configs": 0,
        }

    monkeypatch.setattr(cli_mod, "run_pipeline", fake_run_pipeline)
    code = main([])
    assert code == 0
    options = calls["options"]
    assert options.output_dir == Path("output")
    assert options.from_file is None


def test_run_missing_config_returns_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        [
            "run",
            "--config",
            str(tmp_path / "missing.yaml"),
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )
    assert code == 1
    captured = capsys.readouterr()
    assert "error" in captured.err.lower()


def test_run_missing_from_file_returns_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        [
            "run",
            "--from-file",
            str(tmp_path / "missing.txt"),
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )
    assert code == 1
    captured = capsys.readouterr()
    assert "error" in captured.err.lower()


def test_run_all_sources_failed_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sources_yaml = tmp_path / "sources.yaml"
    sources_yaml.write_text(
        "sources:\n  - name: only\n    url: https://only.invalid/sub\n",
        encoding="utf-8",
    )

    def failing_fetch(source, *, timeout, retries, **kwargs):
        return FetchOutcome(source=source, ok=False, status_code=404, error="HTTP 404")

    monkeypatch.setattr(discovery_engine_mod, "fetch_source", failing_fetch)

    code = main(
        [
            "run",
            "--config",
            str(sources_yaml),
            "--output-dir",
            str(tmp_path / "out"),
            "--discovery-state",
            str(tmp_path / "discovery.json"),
        ]
    )
    assert code == 2
    captured = capsys.readouterr()
    assert "all sources failed" in captured.err


def test_verify_valid_outputs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_dir = tmp_path / "out"
    main(
        [
            "run",
            "--from-file",
            str(FIXTURES / "mixed_subscription.txt"),
            "--output-dir",
            str(output_dir),
        ]
    )
    code = main(["verify", "--output-dir", str(output_dir)])
    assert code == 0
    captured = capsys.readouterr()
    assert "valid" in captured.out


def test_verify_missing_directory(tmp_path: Path) -> None:
    code = main(["verify", "--output-dir", str(tmp_path / "nope")])
    assert code == 1


def test_verify_tampered_base64(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    main(
        [
            "run",
            "--from-file",
            str(FIXTURES / "mixed_subscription.txt"),
            "--output-dir",
            str(output_dir),
        ]
    )
    (output_dir / "subscription_base64.txt").write_text("!!!not-base64!!!\n", encoding="ascii")
    code = main(["verify", "--output-dir", str(output_dir)])
    assert code == 1


def test_verify_missing_file(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    main(
        [
            "run",
            "--from-file",
            str(FIXTURES / "mixed_subscription.txt"),
            "--output-dir",
            str(output_dir),
        ]
    )
    (output_dir / "stats.json").unlink()
    code = main(["verify", "--output-dir", str(output_dir)])
    assert code == 1


def test_verify_stats_inconsistency(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    main(
        [
            "run",
            "--from-file",
            str(FIXTURES / "mixed_subscription.txt"),
            "--output-dir",
            str(output_dir),
        ]
    )
    stats_path = output_dir / "stats.json"
    stats = json.loads(stats_path.read_text(encoding="utf-8"))
    stats["final_configs"] = 999
    stats_path.write_text(json.dumps(stats), encoding="utf-8")
    code = main(["verify", "--output-dir", str(output_dir)])
    assert code == 1


def test_publish_uses_compatibility_min_universal_nodes(tmp_path, monkeypatch):
    import yaml
    from auto_subscription_engine import cli as cli_mod

    testing = tmp_path / "testing.yaml"
    testing.write_text(
        yaml.safe_dump({
            "publish": {"min_live_nodes": 1, "max_drop_ratio": 0.8},
            "security": {"min_publishable_nodes": 1},
            "compatibility": {"min_universal_nodes": 7},
        }),
        encoding="utf-8",
    )
    captured = {}

    class Result:
        decision = "published"
        reasons = []
        live_count = 10
        previous_count = 9
        commit_recommended = False
        commit_message = None
        meaningful_changes = []

    def fake_publish(options):
        captured["min_universal_nodes"] = options.min_universal_nodes
        return Result()

    monkeypatch.setattr(cli_mod, "run_publish", fake_publish)
    monkeypatch.setattr(cli_mod, "resolve_history_baseline", lambda *a, **k: None)
    args = cli_mod.build_parser().parse_args([
        "publish", "--testing-config", str(testing),
        "--output-dir", str(tmp_path / "output"),
        "--public-dir", str(tmp_path / "public"),
        "--history", str(tmp_path / "history.json"),
    ])
    assert cli_mod._cmd_publish(args) == 0
    assert captured["min_universal_nodes"] == 7
