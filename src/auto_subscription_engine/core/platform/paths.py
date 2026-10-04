"""Central temp/runtime path helpers.

All temporary files and runtime binary directories route through here so
no module hardcodes ``/tmp`` or platform-specific locations.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def temp_root() -> Path:
    """Platform-correct temporary directory root."""
    return Path(tempfile.gettempdir())


def runtime_dir(default: Path | str = ".core-bin") -> Path:
    """Directory for checksum-verified core binaries (gitignored)."""
    return Path(default).expanduser().resolve()


def set_owner_only_permissions(path: Path | str) -> None:
    """Restrict a sensitive file to its owner (POSIX 0o600).

    On Windows the POSIX permission model does not exist: os.chmod only
    toggles the read-only flag, so this is a controlled no-op there.
    """
    if os.name == "posix":
        os.chmod(path, 0o600)
