"""End-to-end pipeline tests (offline fixtures and mocked fetchers)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

import auto_subscription_engine.core.discovery.engine as discovery_engine_mod
from auto_subscription_engine.core.discovery import FetchOutcome
from auto_subscription_engine.core.models import SourceConfigError
from auto_subscription_engine.core.orchestration.pipeline import RunOptions, run_pipeline

from conftest import load_fixture

FIXTURES = Path(__file__).parent / "fixtures"


def _offline_options(output_dir: Path) -> RunOptions:
    return RunOptions(
        config_path=Path("config/sources.yaml"),
        output_dir=output_dir,
        from_file=FIXTURES / "mixed_subscription.txt",
    )


def test_offline_pipeline_end_to_end(tmp_path: Path) -> None:
    stats = run_pipeline(_offline_options(tmp_path))

    assert stats["mode"] == "offline"
    assert stats["sources_total"] == 0
    assert stats["sources_success"] == 0
    assert stats["sources_failed"] == 0
    assert stats["configs_received"] == 14
    assert stats["configs_unknown_protocol"] == 1
    assert stats["configs_invalid"] == 4
    assert stats["configs_valid"] == 9
    assert stats["duplicates_removed"] == 3
    assert stats["final_configs"] == 6
    assert stats["count_by_protocol"] == {
        "hysteria2": 1,
        "ss": 1,
        "trojan": 1,
        "vless": 2,
        "vmess": 1,
    }

    text = (tmp_path / "subscription.txt").read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 6

    encoded = (tmp_path / "subscription_base64.txt").read_text(encoding="ascii").strip()
    assert base64.b64decode(encoded).decode("utf-8") == text

    # The duplicate representative is chosen deterministically: both hy2
    # aliases carry a name, so the shorter URI survives (the hysteria2://
    # form minus the longer "#alias" fragment).
    assert any(line.startswith("hysteria2://") for line in lines)
    # Deterministic ordering: protocols appear in sorted order.
    schemes = [line.partition("://")[0] for line in lines]
    assert schemes == sorted(schemes)

    persisted = json.loads((tmp_path / "stats.json").read_text(encoding="utf-8"))
    assert persisted["final_configs"] == 6
    assert "generated_at" in persisted


def test_offline_pipeline_is_deterministic(tmp_path: Path) -> None:
    stats_a = run_pipeline(_offline_options(tmp_path / "run-a"))
    stats_b = run_pipeline(_offline_options(tmp_path / "run-b"))

    text_a = (tmp_path / "run-a" / "subscription.txt").read_text(encoding="utf-8")
    text_b = (tmp_path / "run-b" / "subscription.txt").read_text(encoding="utf-8")
    assert text_a == text_b

    b64_a = (tmp_path / "run-a" / "subscription_base64.txt").read_text(encoding="ascii")
    b64_b = (tmp_path / "run-b" / "subscription_base64.txt").read_text(encoding="ascii")
    assert b64_a == b64_b

    # stats differ only in the generated_at timestamp.
    dict_a = dict(stats_a)
    dict_b = dict(stats_b)
    dict_a.pop("generated_at")
    dict_b.pop("generated_at")
    assert dict_a == dict_b


def test_invalid_reasons_are_recorded(tmp_path: Path) -> None:
    stats = run_pipeline(_offline_options(tmp_path))
    reasons = stats["invalid_reasons"]
    assert reasons.get("unknown protocol") == 1
    assert reasons.get("validate: local or private host") == 2
    assert reasons.get("parse: port is not numeric") == 1
    assert reasons.get("parse: empty payload after scheme") == 1


def test_fetch_mode_with_mocked_fetcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sources_yaml = tmp_path / "sources.yaml"
    sources_yaml.write_text(
        "sources:\n"
        "  - name: good-source\n"
        "    url: https://good.invalid/sub\n"
        "  - name: bad-source\n"
        "    url: https://bad.invalid/sub\n",
        encoding="utf-8",
    )

    base64_content = load_fixture("base64_subscription.txt")

    def fake_fetch(source, *, timeout, retries, **kwargs):
        if source.name == "good-source":
            return FetchOutcome(
                source=source,
                ok=True,
                status_code=200,
                content=base64_content,
                byte_count=len(base64_content.encode()),
            )
        return FetchOutcome(source=source, ok=False, status_code=404, error="HTTP 404")

    monkeypatch.setattr(discovery_engine_mod, "fetch_source", fake_fetch)

    output_dir = tmp_path / "out"
    stats = run_pipeline(
        RunOptions(config_path=sources_yaml, output_dir=output_dir, timeout=5, retries=1)
    )

    assert stats["mode"] == "discovery"
    assert stats["sources_total"] == 2
    assert stats["sources_success"] == 1
    assert stats["sources_failed"] == 1
    assert stats["configs_received"] == 3
    assert stats["final_configs"] == 3

    reports = {report["name"]: report for report in stats["sources"]}
    assert reports["good-source"]["ok"] is True
    assert reports["good-source"]["uri_count"] == 3
    assert reports["bad-source"]["ok"] is False
    assert reports["bad-source"]["error"] == "HTTP 404"


def test_broken_source_never_crashes_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources_yaml = tmp_path / "sources.yaml"
    sources_yaml.write_text(
        "sources:\n  - name: exploding\n    url: https://boom.invalid/sub\n",
        encoding="utf-8",
    )

    def exploding_fetch(source, *, timeout, retries, **kwargs):
        raise RuntimeError("unexpected internal error")

    monkeypatch.setattr(discovery_engine_mod, "fetch_source", exploding_fetch)

    stats = run_pipeline(
        RunOptions(config_path=sources_yaml, output_dir=tmp_path / "out")
    )
    assert stats["sources_failed"] == 1
    assert stats["sources_success"] == 0
    assert stats["final_configs"] == 0
    assert (tmp_path / "out" / "subscription.txt").is_file()


def test_missing_from_file_raises(tmp_path: Path) -> None:
    options = RunOptions(
        config_path=Path("config/sources.yaml"),
        output_dir=tmp_path,
        from_file=tmp_path / "missing.txt",
    )
    with pytest.raises(SourceConfigError):
        run_pipeline(options)


def test_missing_source_config_raises(tmp_path: Path) -> None:
    options = RunOptions(config_path=tmp_path / "nope.yaml", output_dir=tmp_path)
    with pytest.raises(SourceConfigError):
        run_pipeline(options)
