"""Safe archive extraction used by the pinned-core installer.

Supported formats: ``tar.gz``, ``tar.xz``, ``zip`` and single-member ``gz``.
Every member name is validated against traversal, absolute paths, Windows
drive letters and backslash tricks before extraction; extraction is
size-capped and never follows symlink members into arbitrary locations.
"""

from __future__ import annotations

import gzip
import tarfile
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

class ArchiveError(Exception):
    """Raised when an archive cannot be extracted safely."""


def validate_member_name(name: str) -> str:
    """Normalize and validate one archive member path; return the normalized name."""
    if not name or not name.strip():
        raise ArchiveError("empty archive member name")
    # Reject Windows drive letters and UNC paths outright.
    win = PureWindowsPath(name)
    if win.drive or name.startswith("\\\\"):
        raise ArchiveError(f"unsafe archive member (drive/UNC path): {name!r}")
    posix = PurePosixPath(name.replace("\\", "/"))
    parts = [part for part in posix.parts if part not in ("/",)]
    if not parts:
        raise ArchiveError(f"unsafe archive member: {name!r}")
    for part in parts:
        if part in ("..", "."):
            raise ArchiveError(f"unsafe archive member (traversal): {name!r}")
    if posix.is_absolute() or name.startswith(("/", "./", "../")):
        # "./bin" style is acceptable; only the normalized tail is used.
        pass
    normalized = "/".join(parts)
    return normalized


def extract_member(
    archive_path: Path,
    member_name: str,
    dest: Path,
    *,
    max_bytes: int,
    fmt: str | None = None,
) -> None:
    """Extract exactly one validated member into ``dest`` (a file path)."""
    fmt = fmt or _infer_format(archive_path)
    validate_member_name(member_name)
    if fmt == "tar.gz":
        data = _read_tar(archive_path, member_name, max_bytes, mode="r:gz")
    elif fmt == "tar.xz":
        data = _read_tar(archive_path, member_name, max_bytes, mode="r:xz")
    elif fmt == "tar":
        data = _read_tar(archive_path, member_name, max_bytes, mode="r:")
    elif fmt == "zip":
        data = _read_zip(archive_path, member_name, max_bytes)
    elif fmt == "gz":
        data = _read_gz(archive_path, max_bytes, member_name)
    else:
        raise ArchiveError(f"unsupported archive format: {fmt!r}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)


def extract_members(
    archive_path: Path,
    member_names: tuple[str, ...],
    dest_dir: Path,
    *,
    max_bytes: int,
    fmt: str | None = None,
) -> list[Path]:
    """Extract several validated members (flat, by basename) into ``dest_dir``."""
    written: list[Path] = []
    for member in member_names:
        normalized = validate_member_name(member)
        target = dest_dir / Path(normalized).name
        extract_member(archive_path, member, target, max_bytes=max_bytes, fmt=fmt)
        written.append(target)
    return written


def _infer_format(archive_path: Path) -> str:
    name = archive_path.name.lower()
    if name.endswith((".tar.gz", ".tgz")):
        return "tar.gz"
    if name.endswith(".tar.xz"):
        return "tar.xz"
    if name.endswith(".tar"):
        return "tar"
    if name.endswith(".zip"):
        return "zip"
    if name.endswith(".gz"):
        return "gz"
    raise ArchiveError(f"cannot infer archive format from name: {archive_path.name!r}")


def _read_tar(archive_path: Path, member_name: str, max_bytes: int, *, mode: str) -> bytes:
    normalized = validate_member_name(member_name)
    try:
        with tarfile.open(archive_path, mode) as tar:
            member = _find_member(tar, normalized)
            if member is None:
                raise ArchiveError(f"archive member not found: {member_name}")
            if not member.isfile():
                raise ArchiveError(f"archive member is not a regular file: {member_name}")
            extracted = tar.extractfile(member)
            if extracted is None:
                raise ArchiveError(f"cannot read archive member: {member_name}")
            data = extracted.read(max_bytes)
            if len(data) >= max_bytes:
                raise ArchiveError(f"archive member exceeds {max_bytes} bytes")
            return data
    except ArchiveError:
        raise
    except (tarfile.TarError, KeyError, OSError) as exc:
        raise ArchiveError(
            f"cannot extract '{member_name}' from archive: {type(exc).__name__}"
        ) from exc


def _find_member(tar: tarfile.TarFile, normalized: str):
    """Locate a member by its normalized name, tolerating a leading './'."""
    for candidate in (normalized, f"./{normalized}"):
        try:
            return tar.getmember(candidate)
        except KeyError:
            continue
    for member in tar.getmembers():
        if validate_member_name(member.name) == normalized:
            return member
    return None


def _read_zip(archive_path: Path, member_name: str, max_bytes: int) -> bytes:
    normalized = validate_member_name(member_name)
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                if validate_member_name(info.filename) == normalized:
                    if info.is_dir():
                        raise ArchiveError(f"archive member is a directory: {member_name}")
                    if info.file_size > max_bytes:
                        raise ArchiveError(f"archive member exceeds {max_bytes} bytes")
                    return archive.read(info, pwd=None)
            raise ArchiveError(f"archive member not found: {member_name}")
    except ArchiveError:
        raise
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArchiveError(
            f"cannot extract '{member_name}' from archive: {type(exc).__name__}"
        ) from exc


def _read_gz(archive_path: Path, max_bytes: int, member_name: str) -> bytes:
    """Decompress a single-member gzip stream (the binary itself)."""
    validate_member_name(member_name)
    try:
        with gzip.open(archive_path, "rb") as stream:
            data = stream.read(max_bytes)
        if len(data) >= max_bytes:
            raise ArchiveError(f"archive member exceeds {max_bytes} bytes")
        return data
    except ArchiveError:
        raise
    except (OSError, gzip.BadGzipFile, EOFError) as exc:
        raise ArchiveError(
            f"cannot decompress core archive: {type(exc).__name__}"
        ) from exc
