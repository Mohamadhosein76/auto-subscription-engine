"""Tests for output file generation."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from auto_subscription_engine.core.models.fingerprint import normalize_config
from auto_subscription_engine.core.orchestration.output import write_outputs
from auto_subscription_engine.core.protocols import parse_uri

URIS = [
    "trojan://pw@t.example.com:443#t",
    "vless://11111111-2222-3333-4444-555555555555@v.example.com:443#v",
    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@s.example.com:8388#s",
]

STATS = {
    "generated_at": "2026-01-01T00:00:00+00:00",
    "final_configs": 3,
}


def _configs(uris: list[str]):
    return [normalize_config(parse_uri(uri)) for uri in uris]


def test_writes_all_three_files(tmp_path: Path) -> None:
    write_outputs(_configs(URIS), STATS, tmp_path)
    assert (tmp_path / "subscription.txt").is_file()
    assert (tmp_path / "subscription_base64.txt").is_file()
    assert (tmp_path / "stats.json").is_file()


def test_subscription_txt_is_newline_separated(tmp_path: Path) -> None:
    write_outputs(_configs(URIS), STATS, tmp_path)
    text = (tmp_path / "subscription.txt").read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines == URIS
    assert text.endswith("\n")


def test_base64_file_matches_subscription(tmp_path: Path) -> None:
    write_outputs(_configs(URIS), STATS, tmp_path)
    text = (tmp_path / "subscription.txt").read_text(encoding="utf-8")
    encoded = (tmp_path / "subscription_base64.txt").read_text(encoding="ascii").strip()
    assert base64.b64decode(encoded).decode("utf-8") == text


def test_stats_json_roundtrip(tmp_path: Path) -> None:
    write_outputs(_configs(URIS), STATS, tmp_path)
    data = json.loads((tmp_path / "stats.json").read_text(encoding="utf-8"))
    assert data["final_configs"] == 3
    assert data["generated_at"] == "2026-01-01T00:00:00+00:00"


def test_empty_config_set(tmp_path: Path) -> None:
    write_outputs([], {"final_configs": 0}, tmp_path)
    text = (tmp_path / "subscription.txt").read_text(encoding="utf-8")
    assert text == ""
    encoded = (tmp_path / "subscription_base64.txt").read_text(encoding="ascii").strip()
    assert base64.b64decode(encoded).decode("utf-8") == ""


def test_output_directory_created(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "deep" / "out"
    write_outputs([], {"final_configs": 0}, target)
    assert target.is_dir()
    assert (target / "stats.json").is_file()
