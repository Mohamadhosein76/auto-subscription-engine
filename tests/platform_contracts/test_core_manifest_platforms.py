"""Core manifest cross-platform contract tests."""

from __future__ import annotations

import pytest

from auto_subscription_engine.core.clients.install import (
    CoreInstallError,
    specs_from_testing_config,
)
from auto_subscription_engine.core.platform import SUPPORTED_PLATFORMS


def _testing_config():
    import yaml

    return yaml.safe_load(
        open("config/testing.yaml", encoding="utf-8")
    )


def test_every_core_declares_linux_amd64_and_windows_amd64():
    cfg = _testing_config()
    cores = {"singbox": cfg.get("singbox", {}), **cfg.get("cores", {})}
    for key, entry in cores.items():
        platforms = entry.get("platforms") or {}
        assert "linux-amd64" in platforms, f"core {key} missing linux-amd64"
        assert "windows-amd64" in platforms, f"core {key} missing windows-amd64"


def test_every_pinned_digest_is_a_real_sha256():
    cfg = _testing_config()
    cores = {"singbox": cfg.get("singbox", {}), **cfg.get("cores", {})}
    for key, entry in cores.items():
        for platform_id, artifact in (entry.get("platforms") or {}).items():
            digest = artifact.get("archive_sha256", "")
            assert len(digest) == 64, f"{key}/{platform_id}: bad digest length"
            assert all(ch in "0123456789abcdef" for ch in digest)


def test_specs_resolve_for_both_platforms():
    cfg = _testing_config()
    for platform_id in ("linux-amd64", "windows-amd64"):
        specs = specs_from_testing_config(cfg, platform_id=platform_id)
        assert set(specs) == {"singbox", "xray", "hiddify", "mihomo"}
        for key, spec in specs.items():
            assert spec.platform == platform_id


def test_unknown_platform_fails_closed():
    cfg = _testing_config()
    specs = specs_from_testing_config(cfg, platform_id="sunos-sparc")
    assert specs == {}, "no core may be installed without a pinned artifact"


def test_windows_artifacts_point_at_official_releases():
    cfg = _testing_config()
    specs = specs_from_testing_config(cfg, platform_id="windows-amd64")
    hosts = {spec.url_template.split("/")[2] for spec in specs.values()}
    assert hosts == {"github.com"}
    for spec in specs.values():
        assert "/releases/download/" in spec.url_template
        assert "latest" not in spec.url_template


def test_flat_legacy_schema_still_resolves():
    cfg = {
        "cores": {
            "xray": {
                "version": "1.2.3",
                "archive_sha256": "a" * 64,
                "url_template": "https://github.com/x/releases/download/v{version}/Xray-linux-64.zip",
                "binary_path_in_archive": "xray",
                "format": "zip",
            }
        }
    }
    specs = specs_from_testing_config(cfg, platform_id="linux-amd64")
    assert specs["xray"].platform == "linux-amd64"
    assert specs["xray"].binary_name == "xray"


def test_spec_platform_defaults_to_running_platform():
    from auto_subscription_engine.core.platform import current_platform

    spec = CoreSpecFactory()
    assert spec.platform == current_platform()


def CoreSpecFactory():
    from auto_subscription_engine.core.clients.install import CoreBinarySpec

    return CoreBinarySpec(
        key="xray",
        version="1",
        archive_sha256="a" * 64,
        url_template="https://github.com/x/releases/download/v{version}/a",
        binary_path_in_archive="xray",
        format="zip",
    )
