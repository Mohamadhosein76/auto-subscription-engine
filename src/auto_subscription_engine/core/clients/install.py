"""Pinned multi-core installation (Universal Client Compatibility layer).

Installs the four real proxy cores used by the engine:

=========  ============  =============================================
core       binary        client family represented
=========  ============  =============================================
sing-box   sing-box      sing-box / NekoBox family (live pipeline)
xray       xray          v2rayNG / v2rayN (Xray-core)
hiddify    hiddify-core  Hiddify (sing-box fork, version reported by
                         the binary itself)
mihomo     mihomo        Clash Meta / Mihomo / Clash.Meta family
=========  ============  =============================================

Supply-chain rules enforced for every core:

- official GitHub release only (pinned URL template, no floating latest);
- exact version AND exact archive SHA-256 pinned in config/testing.yaml;
- download size cap enforced while streaming;
- checksum verified with a constant-time comparison *before* extraction;
- safe extraction of exactly one known member (no traversal);
- the binary is written into a gitignored runtime dir, never committed;
- archives are removed after extraction (temp cleanup);
- per-core identity marker makes re-installation idempotent.

If any core cannot be installed/verified, the compatibility engine
simply reports that core as ``unavailable``: the affected client feed is
NOT published (previous-good preservation) and the universal feed is
never produced from unverified cores.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import logging
import os
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

#: Default per-archive download cap (all pinned archives are < 40 MB).
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
_DOWNLOAD_CHUNK = 256 * 1024

#: Canonical core keys used across the engine.
CORE_KEYS = ("singbox", "xray", "hiddify", "mihomo")


class CoreInstallError(Exception):
    """Raised when a pinned core cannot be installed or verified."""


class ChecksumError(CoreInstallError):
    """Raised when the downloaded archive does not match the pinned digest."""


@dataclass(frozen=True)
class CoreBinarySpec:
    """Pinned identity of one core binary archive.

    ``format`` is one of:

    - ``tar.gz``: gzipped tar containing ``binary_path_in_archive``;
    - ``zip``:   zip archive containing ``binary_path_in_archive``;
    - ``gz``:    single-member gzip whose decompressed stream IS the
                 binary (``binary_path_in_archive`` names the extracted
                 file to write).
    """

    key: str
    version: str
    archive_sha256: str
    url_template: str
    binary_path_in_archive: str
    format: str
    max_bytes: int = MAX_ARCHIVE_BYTES

    @property
    def binary_name(self) -> str:
        """File name the extracted binary is installed as."""
        return {"singbox": "sing-box", "xray": "xray", "hiddify": "hiddify-core",
                "mihomo": "mihomo"}[self.key]


def specs_from_config(cores_cfg: dict) -> dict[str, CoreBinarySpec]:
    """Build the pinned spec mapping from the ``cores`` testing config."""
    specs: dict[str, CoreBinarySpec] = {}
    for key in ("singbox", "xray", "hiddify", "mihomo"):
        raw = cores_cfg.get(key)
        if not isinstance(raw, dict) or not raw.get("version"):
            continue
        fmt = str(raw.get("format", "tar.gz"))
        if fmt not in ("tar.gz", "zip", "gz"):
            raise CoreInstallError(f"core {key}: unsupported archive format {fmt!r}")
        digest = str(raw.get("archive_sha256", "")).strip().lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise CoreInstallError(f"core {key}: pinned archive_sha256 is not a SHA-256")
        version = str(raw["version"])
        member = str(raw.get("binary_path_in_archive") or raw.get("archive_binary_path") or "")
        member = member.format(version=version)
        specs[key] = CoreBinarySpec(
            key=key,
            version=version,
            archive_sha256=digest,
            url_template=str(raw["url_template"]),
            binary_path_in_archive=member,
            format=fmt,
            max_bytes=int(raw.get("max_bytes", MAX_ARCHIVE_BYTES)),
        )
    return specs



def specs_from_testing_config(testing_cfg: dict) -> dict[str, CoreBinarySpec]:
    """Build all four pinned core specs from the full testing config.

    ``singbox`` historically lived in its own top-level section while the
    other cores lived under ``cores``.  Stage 7 keeps the file format stable
    but normalizes both locations into one installer model.
    """
    combined: dict = {}
    singbox = testing_cfg.get("singbox")
    if isinstance(singbox, dict):
        combined["singbox"] = {**singbox, "format": singbox.get("format", "tar.gz")}
    cores = testing_cfg.get("cores")
    if isinstance(cores, dict):
        combined.update(cores)
    specs = specs_from_config(combined)
    return specs

def install_core_binary(
    dest_dir: Path,
    spec: CoreBinarySpec,
    *,
    session: requests.Session | None = None,
) -> Path:
    """Install one pinned core binary (idempotent, checksum-verified)."""
    session = session or requests.Session()
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    binary_path = dest_dir / spec.binary_name
    marker_path = dest_dir / f"{spec.binary_name}.ok"
    expected_marker = f"{spec.key}\n{spec.version}\n{spec.archive_sha256}\n"

    if binary_path.is_file() and marker_path.is_file():
        try:
            if marker_path.read_text(encoding="utf-8") == expected_marker:
                logger.info("pinned core %s %s already installed", spec.key, spec.version)
                return binary_path
        except OSError:
            pass

    url = spec.url_template.format(version=spec.version)
    logger.info("downloading pinned core %s %s from official release", spec.key, spec.version)
    fd, archive_name = tempfile.mkstemp(dir=str(dest_dir), suffix=".archive")
    os.close(fd)
    archive_path = Path(archive_name)
    try:
        downloaded = 0
        digest = hashlib.sha256()
        try:
            with session.get(url, stream=True, timeout=120.0) as response:
                response.raise_for_status()
                with archive_path.open("wb") as handle:
                    for chunk in response.iter_content(chunk_size=_DOWNLOAD_CHUNK):
                        if not chunk:
                            continue
                        downloaded += len(chunk)
                        if downloaded > spec.max_bytes:
                            raise CoreInstallError(
                                f"core {spec.key} archive exceeds {spec.max_bytes} bytes"
                            )
                        digest.update(chunk)
                        handle.write(chunk)
        except requests.RequestException as exc:
            raise CoreInstallError(
                f"core {spec.key} download failed: {type(exc).__name__}"
            ) from exc

        actual = digest.hexdigest()
        if not hmac.compare_digest(actual, spec.archive_sha256.lower()):
            raise ChecksumError(
                f"core {spec.key} archive checksum mismatch: "
                f"expected {spec.archive_sha256}, got {actual}"
            )

        _extract_member(archive_path, spec, binary_path)
    finally:
        try:
            archive_path.unlink()
        except OSError:
            pass

    marker_path.write_text(expected_marker, encoding="utf-8")
    logger.info("core %s %s installed (checksum verified)", spec.key, spec.version)
    return binary_path


def _extract_member(archive_path: Path, spec: CoreBinarySpec, dest: Path) -> None:
    """Extract exactly one known member (path-safe, size-capped)."""
    if spec.format == "tar.gz":
        _extract_tar_gz(archive_path, spec.binary_path_in_archive, dest, spec.max_bytes)
    elif spec.format == "zip":
        _extract_zip(archive_path, spec.binary_path_in_archive, dest, spec.max_bytes)
    else:
        _extract_gz(archive_path, dest, spec.max_bytes)
    dest.chmod(0o755)


def _extract_tar_gz(archive_path: Path, member_name: str, dest: Path, max_bytes: int) -> None:
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            member = tar.getmember(member_name)
            if not member.isfile():
                raise CoreInstallError(f"archive member is not a file: {member_name}")
            extracted = tar.extractfile(member)
            if extracted is None:
                raise CoreInstallError(f"cannot read archive member: {member_name}")
            data = extracted.read(max_bytes)
    except (tarfile.TarError, KeyError) as exc:
        raise CoreInstallError(
            f"cannot extract '{member_name}' from core archive: {type(exc).__name__}"
        ) from exc
    dest.write_bytes(data)


def _extract_zip(archive_path: Path, member_name: str, dest: Path, max_bytes: int) -> None:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.getinfo(member_name)
            if info.is_dir():
                raise CoreInstallError(f"archive member is a directory: {member_name}")
            if info.file_size > max_bytes:
                raise CoreInstallError(f"archive member exceeds {max_bytes} bytes")
            data = archive.read(member_name, pwd=None)
    except (zipfile.BadZipFile, KeyError) as exc:
        raise CoreInstallError(
            f"cannot extract '{member_name}' from core archive: {type(exc).__name__}"
        ) from exc
    dest.write_bytes(data)


def _extract_gz(archive_path: Path, dest: Path, max_bytes: int) -> None:
    """Decompress a single-member gzip stream (the binary itself)."""
    try:
        with gzip.open(archive_path, "rb") as stream:
            data = stream.read(max_bytes)
    except (OSError, gzip.BadGzipFile, EOFError) as exc:
        raise CoreInstallError(
            f"cannot decompress core archive: {type(exc).__name__}"
        ) from exc
    dest.write_bytes(data)


def verify_installed(dest_dir: Path, spec: CoreBinarySpec) -> Path | None:
    """Return the binary path when the pinned core is installed+verified."""
    dest_dir = Path(dest_dir)
    binary_path = dest_dir / spec.binary_name
    marker_path = dest_dir / f"{spec.binary_name}.ok"
    expected_marker = f"{spec.key}\n{spec.version}\n{spec.archive_sha256}\n"
    if binary_path.is_file() and marker_path.is_file():
        try:
            if marker_path.read_text(encoding="utf-8") == expected_marker:
                return binary_path
        except OSError:
            pass
    return None


def verified_core_paths(dest_dir: Path, testing_cfg: dict) -> dict[str, Path]:
    """Return checksum-marker-verified core binaries available in ``dest_dir``."""
    specs = specs_from_testing_config(testing_cfg)
    found: dict[str, Path] = {}
    for key, spec in specs.items():
        path = verify_installed(dest_dir, spec)
        if path is not None:
            found[key] = path
    return found
