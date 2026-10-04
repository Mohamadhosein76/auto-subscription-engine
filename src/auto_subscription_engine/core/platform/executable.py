"""Central executable naming and resolution.

A core's installed file name depends on the platform: POSIX cores install
without an extension while Windows cores require ``.exe``.  Every runtime
engine resolves binaries through this module only.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Base file names (without platform extension) for every supported core.
CORE_BINARY_BASE_NAMES = {
    "singbox": "sing-box",
    "xray": "xray",
    "hiddify": "hiddify-core",
    "mihomo": "mihomo",
}

#: Cores whose Windows artifact ships under a distinct CLI entry point.
_WINDOWS_BINARY_OVERRIDES = {
    # The hiddify-core Windows release ships the core runtime as
    # HiddifyCli.exe (plus its DLLs); there is no hiddify-core.exe.
    "hiddify": "HiddifyCli",
}


def binary_base_name(core: str) -> str:
    """Base (extension-less) install name of a core binary."""
    try:
        return CORE_BINARY_BASE_NAMES[core]
    except KeyError as exc:
        raise ValueError(f"unknown core: {core!r}") from exc


def binary_file_name(core: str, platform_id: str) -> str:
    """Platform-correct installed file name for a core binary."""
    base = binary_base_name(core)
    if platform_id.startswith("windows-"):
        return _WINDOWS_BINARY_OVERRIDES.get(core, base) + ".exe"
    return base


def resolve_executable(path: Path | str) -> Path:
    """Resolve a binary path to its platform-correct existing file.

    Accepts either the bare install name or a full path and returns the
    first existing candidate (with and without ``.exe``).  Raises
    ``FileNotFoundError`` when no candidate exists.
    """
    path = Path(path)
    if path.is_file():
        return path
    if not path.suffix:
        with_exe = path.with_name(path.name + ".exe")
        if with_exe.is_file():
            return with_exe
    raise FileNotFoundError(f"executable not found: {path}")


def ensure_executable(path: Path | str) -> Path:
    """Make a binary executable (POSIX chmod; a no-op on Windows)."""
    path = Path(path)
    if os.name == "posix":
        import stat

        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path
