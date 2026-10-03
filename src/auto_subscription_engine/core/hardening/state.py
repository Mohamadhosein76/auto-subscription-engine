"""Durable JSON state I/O for production runs.

State files are credential-free but operationally important.  A truncated or
corrupt state file must never be silently interpreted as an empty database,
because that destroys scheduler/source/operator history and can cause a large
behaviour change in the next publish.

Writes use a same-filesystem temporary file, fsync, atomic replace and a
last-known-good ``.bak`` snapshot.  Reads recover from that backup when
possible and otherwise fail closed with :class:`StateCorruptionError`.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any


class StateCorruptionError(RuntimeError):
    """An existing persistent state file cannot be safely decoded."""


def backup_path(path: Path) -> Path:
    path = Path(path)
    return path.with_name(path.name + ".bak")


def _fsync_dir(path: Path) -> None:
    """Best-effort directory fsync after rename/create operations."""
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _decode_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateCorruptionError(f"state file is unreadable: {path}: {exc}") from exc


def load_json_state(path: Path | None, *, recover_backup: bool = True) -> Any | None:
    """Read one JSON state file.

    Missing files are normal and return ``None``.  Existing corrupt files are
    recovered from ``<name>.bak`` when available.  If neither copy is valid,
    fail closed instead of silently resetting state.
    """
    if path is None:
        return None
    path = Path(path)
    if not path.is_file():
        return None
    try:
        return _decode_json(path)
    except StateCorruptionError as primary_error:
        backup = backup_path(path)
        if not recover_backup or not backup.is_file():
            raise primary_error
        recovered = _decode_json(backup)
        # Repair the primary copy immediately so later stages see the same
        # state.  This is still atomic and preserves the backup.
        atomic_write_json(path, recovered, make_backup=False)
        return recovered


def atomic_write_text(
    path: Path,
    text: str,
    *,
    encoding: str = "utf-8",
    make_backup: bool = True,
    mode: int = 0o600,
) -> None:
    """Durably and atomically replace ``path`` with ``text``."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if make_backup and path.is_file():
        backup = backup_path(path)
        fd, backup_tmp = tempfile.mkstemp(
            dir=str(path.parent), prefix=f".{path.name}.bak-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                with path.open("rb") as source:
                    shutil.copyfileobj(source, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(backup_tmp, mode)
            os.replace(backup_tmp, backup)
            _fsync_dir(path.parent)
        except Exception:
            try:
                os.unlink(backup_tmp)
            except OSError:
                pass
            raise

    fd, temp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
        _fsync_dir(path.parent)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def atomic_write_json(
    path: Path,
    payload: Any,
    *,
    make_backup: bool = True,
    sort_keys: bool = True,
    ensure_ascii: bool = False,
    mode: int = 0o600,
) -> None:
    text = json.dumps(
        payload,
        indent=2,
        sort_keys=sort_keys,
        ensure_ascii=ensure_ascii,
    ) + "\n"
    atomic_write_text(path, text, make_backup=make_backup, mode=mode)
