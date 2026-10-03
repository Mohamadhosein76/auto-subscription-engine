"""Tests for the Task 2 CLI commands (live, core-install, verify-live)."""

from __future__ import annotations

from pathlib import Path

from auto_subscription_engine.cli import build_parser, main


def test_live_command_defaults():
    args = build_parser().parse_args(["live"])
    assert args.config == Path("config/sources.yaml")
    assert args.testing_config == Path("config/testing.yaml")
    assert args.core_dir == Path(".core-bin")
    assert args.history is None
    assert args.preflight_budget is None
    assert args.runtime_budget is None


def test_verify_live_missing_dir_returns_error(tmp_path):
    code = main(["verify-live", "--output-dir", str(tmp_path / "nothing")])
    assert code == 1


def test_verify_live_invalid_outputs_return_error(tmp_path):
    (tmp_path / "output").mkdir()
    code = main(["verify-live", "--output-dir", str(tmp_path / "output")])
    assert code == 1


def test_live_missing_core_returns_error(tmp_path):
    code = main(
        [
            "live",
            "--output-dir", str(tmp_path / "out"),
            "--core-dir", str(tmp_path / "missing-core-dir"),
            "--testing-config", str(tmp_path / "no-testing.yaml"),
        ]
    )
    assert code == 1


def test_core_install_with_unreachable_source_returns_error(tmp_path):
    testing_config = tmp_path / "testing.yaml"
    testing_config.write_text(
        "singbox:\n"
        "  version: \"0.0.0\"\n"
        "  archive_sha256: \"" + "0" * 64 + "\"\n"
        "  url_template: \"http://127.0.0.1:1/core-{version}.tar.gz\"\n"
        "  archive_binary_path: \"core-{version}/sing-box\"\n",
        encoding="utf-8",
    )
    code = main(
        [
            "core-install",
            "--dest", str(tmp_path / "core-bin"),
            "--testing-config", str(testing_config),
        ]
    )
    assert code == 1
