"""Platform detection contract tests (real platform, not monkeypatched)."""

from __future__ import annotations

import platform

import pytest

from auto_subscription_engine.core.platform import (
    SUPPORTED_PLATFORMS,
    canonical_platform,
    current_platform,
    is_posix,
    is_windows,
)


def test_current_platform_is_canonical():
    assert current_platform() in SUPPORTED_PLATFORMS


def test_current_platform_matches_interpreter():
    expected_os = platform.system().lower()
    assert current_platform().startswith(expected_os)


def test_canonical_mapping_explicit_inputs():
    assert canonical_platform("Windows", "AMD64") == "windows-amd64"
    assert canonical_platform("Linux", "x86_64") == "linux-amd64"
    assert canonical_platform("Darwin", "arm64") == "darwin-arm64"
    assert canonical_platform("Linux", "aarch64") == "linux-arm64"
    assert canonical_platform("Windows", "ARM64") == "windows-arm64"


def test_canonical_rejects_unknown_system():
    with pytest.raises(ValueError):
        canonical_platform("SunOS", "x86_64")


def test_is_windows_is_posix_disjoint():
    assert is_windows() != is_posix()
