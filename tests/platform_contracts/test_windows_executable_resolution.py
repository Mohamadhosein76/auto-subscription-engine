"""Executable naming/resolution contract tests (run on the real platform)."""

from __future__ import annotations

from auto_subscription_engine.core.platform import (
    binary_base_name,
    binary_file_name,
    resolve_executable,
)


def test_base_names_are_stable():
    assert binary_base_name("xray") == "xray"
    assert binary_base_name("singbox") == "sing-box"
    assert binary_base_name("mihomo") == "mihomo"
    assert binary_base_name("hiddify") == "hiddify-core"


def test_windows_names_carry_exe_suffix():
    assert binary_file_name("xray", "windows-amd64") == "xray.exe"
    assert binary_file_name("singbox", "windows-amd64") == "sing-box.exe"
    assert binary_file_name("mihomo", "windows-amd64") == "mihomo.exe"
    # The hiddify Windows artifact ships its runtime as HiddifyCli.exe.
    assert binary_file_name("hiddify", "windows-amd64") == "HiddifyCli.exe"


def test_posix_names_have_no_suffix():
    for core in ("xray", "singbox", "mihomo", "hiddify"):
        name = binary_file_name(core, "linux-amd64")
        assert not name.endswith(".exe")


def test_resolve_executable_finds_exe_candidate(tmp_path):
    exe = tmp_path / "xray.exe"
    exe.write_bytes(b"fake")
    assert resolve_executable(tmp_path / "xray") == exe


def test_resolve_executable_prefers_existing_bare_name(tmp_path):
    bare = tmp_path / "xray"
    bare.write_bytes(b"fake")
    assert resolve_executable(tmp_path / "xray") == bare


def test_resolve_executable_missing_raises(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        resolve_executable(tmp_path / "missing-core")
