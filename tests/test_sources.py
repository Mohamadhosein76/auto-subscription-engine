"""Tests for the source manager (config loading and URL validation)."""

from __future__ import annotations

from pathlib import Path

import pytest

from auto_subscription_engine.core.models import SourceConfigError
from auto_subscription_engine.core.discovery import load_source_catalog, validate_source_url


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "sources.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_load_valid_sources(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "sources:\n"
        "  - name: alpha\n"
        "    url: https://alpha.example.com/sub\n"
        "  - name: beta\n"
        "    url: http://beta.example.com/sub\n",
    )
    sources = load_source_catalog(path)
    assert [source.name for source in sources] == ["alpha", "beta"]
    assert sources[0].url == "https://alpha.example.com/sub"


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(tmp_path / "nope.yaml")


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(_write(tmp_path, "sources: [unclosed"))


def test_non_mapping_raises(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(_write(tmp_path, "- just\n- a list\n"))


def test_missing_sources_key_raises(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(_write(tmp_path, "something_else: 1\n"))


def test_empty_sources_list_raises(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(_write(tmp_path, "sources: []\n"))


def test_entry_missing_url_raises(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(_write(tmp_path, "sources:\n  - name: alpha\n"))


def test_entry_missing_name_raises(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(_write(tmp_path, "sources:\n  - url: https://a.example.com/s\n"))


def test_unknown_entry_keys_raises(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(
            _write(
                tmp_path,
                "sources:\n"
                "  - name: alpha\n"
                "    url: https://a.example.com/s\n"
                "    unexpected: true\n",
            )
        )


def test_duplicate_names_raises(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(
            _write(
                tmp_path,
                "sources:\n"
                "  - name: alpha\n"
                "    url: https://a.example.com/s\n"
                "  - name: alpha\n"
                "    url: https://b.example.com/s\n",
            )
        )


def test_non_http_scheme_rejected(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(
            _write(tmp_path, "sources:\n  - name: ftp\n    url: ftp://a.example.com/f\n")
        )


def test_localhost_url_rejected(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(
            _write(
                tmp_path, "sources:\n  - name: local\n    url: http://localhost:8080/sub\n"
            )
        )


def test_private_ip_url_rejected(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(
            _write(
                tmp_path, "sources:\n  - name: priv\n    url: https://192.168.1.5/sub\n"
            )
        )


def test_embedded_credentials_rejected(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(
            _write(
                tmp_path,
                "sources:\n  - name: cred\n    url: https://user:pass@a.example.com/sub\n",
            )
        )


def test_missing_host_rejected(tmp_path: Path) -> None:
    with pytest.raises(SourceConfigError):
        load_source_catalog(_write(tmp_path, "sources:\n  - name: nohost\n    url: https:///sub\n"))


def test_validate_source_url_accepts_public_http() -> None:
    assert validate_source_url("https://example.com/sub") is None
    assert validate_source_url("http://example.com:8080/sub") is None


def test_validate_source_url_rejects_other_schemes() -> None:
    assert validate_source_url("ftp://example.com/x") is not None
    assert validate_source_url("file:///etc/passwd") is not None
    assert validate_source_url("javascript:alert(1)") is not None


def test_validate_source_url_rejects_local_hosts() -> None:
    assert validate_source_url("http://127.0.0.1/sub") is not None
    assert validate_source_url("http://[::1]/sub") is not None
    assert validate_source_url("http://10.0.0.1/sub") is not None
    assert validate_source_url("http://box.local/sub") is not None


def test_validate_source_url_rejects_bad_port() -> None:
    assert validate_source_url("http://example.com:99999/sub") is not None
