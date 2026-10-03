"""Task 4 tests: CLI wiring for security-check and verify-security."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auto_subscription_engine import cli
from auto_subscription_engine.cli import main
from auto_subscription_engine.core.security.engine import SecurityStageResult


def test_parser_has_security_commands():
    parser = cli.build_parser()
    args = parser.parse_args(["security-check", "--output-dir", "out"])
    assert args.command == "security-check"
    args = parser.parse_args(["verify-security"])
    assert args.command == "verify-security"


def test_security_check_ok_prints_machine_json(tmp_path: Path, capsys, monkeypatch):
    output = tmp_path / "output"
    output.mkdir()

    def _fake(options):
        assert options.output_dir == output
        result = SecurityStageResult(status="ok", live_total=10, publishable_total=8,
                                     selected_total=6)
        return result

    monkeypatch.setattr(cli, "run_security_stage", _fake)
    code = main(["security-check", "--output-dir", str(output)])
    assert code == 0
    captured = capsys.readouterr().out
    assert "SECURITY_JSON=" in captured
    payload = json.loads(captured.split("SECURITY_JSON=", 1)[1].splitlines()[0])
    assert payload["status"] == "ok"
    assert payload["publishable_total"] == 8


def test_security_check_unavailable_exit_code(tmp_path: Path, capsys, monkeypatch):
    output = tmp_path / "output"
    output.mkdir()

    def _fake(options):
        return SecurityStageResult(
            status="security_data_unavailable",
            reason="required feed spamhaus_drop is unavailable",
        )

    monkeypatch.setattr(cli, "run_security_stage", _fake)
    code = main(["security-check", "--output-dir", str(output)])
    assert code == 4  # _EXIT_SECURITY_UNAVAILABLE
    captured = capsys.readouterr()
    assert "SECURITY_JSON=" in captured.out
    payload = json.loads(captured.out.split("SECURITY_JSON=", 1)[1].splitlines()[0])
    assert payload["status"] == "security_data_unavailable"
    assert "previous healthy output" in captured.err


def test_verify_security_invalid_dir_exit_code(tmp_path: Path, capsys):
    code = main(["verify-security", "--output-dir", str(tmp_path / "nope")])
    assert code == 1
    assert "not found" in capsys.readouterr().err


def test_verify_security_valid_outputs_exit_zero(tmp_path: Path, capsys, monkeypatch):
    # minimal stub: monkeypatch the verifier used by the CLI handler
    problems: list[str] = []

    def _fake_verify(output_dir, testing_config_path=None):
        return list(problems)

    monkeypatch.setattr(cli, "verify_security_outputs", _fake_verify)
    output = tmp_path / "output"
    output.mkdir()
    code = main(["verify-security", "--output-dir", str(output)])
    assert code == 0
    problems.append("boom")
    code = main(["verify-security", "--output-dir", str(output)])
    assert code == 1
    assert "boom" in capsys.readouterr().err
