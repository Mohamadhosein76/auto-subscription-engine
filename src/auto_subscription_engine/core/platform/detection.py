"""Canonical platform detection.

``platform.system()``/``platform.machine()`` are mapped onto one canonical
identifier used across configs, manifests and installers:

    linux-amd64 | linux-arm64 | windows-amd64 | windows-arm64
    | darwin-amd64 | darwin-arm64

No other module may detect the platform itself.
"""

from __future__ import annotations

import platform
import re

#: Canonical platform identifiers understood by core manifests.
SUPPORTED_PLATFORMS = (
    "linux-amd64",
    "linux-arm64",
    "windows-amd64",
    "windows-arm64",
    "darwin-amd64",
    "darwin-arm64",
)

_MACHINE_MAP = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "i686": "amd64",   # 32-bit x86 maps to the amd64 artifact family
    "i386": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}

_SYSTEM_MAP = {
    "linux": "linux",
    "windows": "windows",
    "darwin": "darwin",
}


def canonical_platform(system: str | None = None, machine: str | None = None) -> str:
    """Map ``(system, machine)`` to a canonical ``<os>-<arch>`` identifier."""
    system = (system or platform.system()).lower()
    machine_raw = (machine or platform.machine()).lower()
    machine = _MACHINE_MAP.get(machine_raw)
    if machine is None:
        # Some Windows Pythons report "ARM64" or unusual builds; strip noise.
        normalized = re.sub(r"[^a-z0-9]", "", machine_raw)
        machine = _MACHINE_MAP.get(normalized, "amd64")
    os_name = _SYSTEM_MAP.get(system)
    if os_name is None:
        raise ValueError(f"unsupported platform system: {system!r}")
    return f"{os_name}-{machine}"


def current_platform() -> str:
    """Canonical identifier of the running interpreter's platform."""
    return canonical_platform()


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_posix() -> bool:
    import os

    return os.name == "posix"
