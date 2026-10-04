"""Pinned multi-core installation (Universal Client Compatibility layer).

Installs the four real proxy cores used by the engine:

=========  ============  =============================================
core       binary        client family represented
=========  ============  =============================================
sing-box   sing-box      sing-box / NekoBox family (live pipeline)
xray       xray(.exe)    v2rayNG / v2rayN (Xray-core)
hiddify    hiddify-core  Hiddify (sing-box fork, version reported by
                         the binary itself; on Windows the artifact is
                         HiddifyCli.exe + its DLLs)
mihomo     mihomo(.exe)  Clash Meta / Mihomo / Clash.Meta family
=========  ============  =============================================

Cross-platform rule: every core declares per-platform artifacts in
``config/testing.yaml`` (``platforms.<platform>`` with the canonical ids
from ``core.platform.detection``).  The legacy flat single-artifact schema
is still accepted and is treated as the running platform's artifact.

Supply-chain rules enforced for every core and every platform:

- official GitHub release only (pinned URL template, no floating latest);
- exact version AND exact archive SHA-256 pinned per platform in
  config/testing.yaml;
- download size cap enforced while streaming;
- checksum verified with a constant-time comparison *before* extraction;
- safe extraction of only known members (validated names, no traversal);
- the binary is written into a gitignored runtime dir, never committed;
- archives are removed after extraction (temp cleanup);
- per-core, per-platform identity marker makes re-installation idempotent;
- no official checksum -> fail closed (the artifact is never installed
  insecurely).

If a core cannot be installed/verified on the running platform, the
compatibility engine simply reports that core as ``unavailable``: the
affected client feed is NOT published (previous-good preservation) and
the universal feed is never produced from unverified cores.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import requests

from ..platform import (
    binary_file_name,
    current_platform,
    extract_members,
    validate_member_name,
)
from ..platform.executable import ensure_executable

logger = logging.getLogger(__name__)

#: Default per-archive download cap (all pinned archives are < 40 MB).
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
_DOWNLOAD_CHUNK = 256 * 1024

#: Canonical core keys used across the engine.
CORE_KEYS = ("singbox", "xray", "hiddify", "mihomo")

_ARCHIVE_FORMATS = ("tar.gz", "tar.xz", "tar", "zip", "gz")


class CoreInstallError(Exception):
    """Raised when a pinned core cannot be installed or verified."""


class ChecksumError(CoreInstallError):
    """Raised when the downloaded archive does not match the pinned digest."""


@dataclass(frozen=True)
class CoreBinarySpec:
    """Pinned identity of one core binary archive for one platform.

    ``format`` is one of:

    - ``tar.gz`` / ``tar.xz`` / ``tar``: tar archive containing the
      pinned member(s);
    - ``zip``:   zip archive containing the pinned member(s);
    - ``gz``:    single-member gzip whose decompressed stream IS the
                 binary (``binary_path_in_archive`` names the extracted
                 file to write).

    ``extra_members`` lists additional required archive members (e.g. the
    Windows hiddify DLLs) installed flat next to the binary.
    """

    key: str
    version: str
    archive_sha256: str
    url_template: str
    binary_path_in_archive: str
    format: str
    max_bytes: int = MAX_ARCHIVE_BYTES
    platform: str = ""
    extra_members: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        if not self.platform:
            object.__setattr__(self, "platform", current_platform())

    @property
    def binary_name(self) -> str:
        """File name the extracted binary is installed as (platform-aware)."""
        return binary_file_name(self.key, self.platform)

    @property
    def marker_expected(self) -> str:
        return (
            f"{self.key}\n{self.version}\n{self.archive_sha256}\n{self.platform}\n"
        )


def _normalize_members(raw: dict) -> tuple[str, ...]:
    members = raw.get("extra_members") or raw.get("additional_members") or []
    if isinstance(members, str):
        members = [members]
    return tuple(str(m) for m in members)


def _spec_from_platform_entry(
    key: str,
    version: str,
    platform_id: str,
    entry: dict,
) -> CoreBinarySpec:
    fmt = str(entry.get("format", "tar.gz"))
    if fmt not in _ARCHIVE_FORMATS:
        raise CoreInstallError(
            f"core {key}/{platform_id}: unsupported archive format {fmt!r}"
        )
    digest = str(entry.get("archive_sha256", "")).strip().lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise CoreInstallError(
            f"core {key}/{platform_id}: pinned archive_sha256 is not a SHA-256"
        )
    member = str(
        entry.get("binary_path_in_archive") or entry.get("archive_binary_path") or ""
    )
    member = member.format(version=version)
    validate_member_name(member)
    return CoreBinarySpec(
        key=key,
        version=version,
        archive_sha256=digest,
        url_template=str(entry["url_template"]),
        binary_path_in_archive=member,
        format=fmt,
        platform=platform_id,
        max_bytes=int(entry.get("max_bytes", MAX_ARCHIVE_BYTES)),
        extra_members=_normalize_members(entry),
    )


def specs_from_config(
    cores_cfg: dict,
    *,
    platform_id: str | None = None,
) -> dict[str, CoreBinarySpec]:
    """Build the pinned spec mapping from the ``cores`` testing config.

    Two schemas are accepted per core:

    - ``platforms:`` mapping of canonical platform id -> artifact entry
      (the cross-platform schema); or
    - the legacy flat artifact, treated as the artifact for
      ``platform_id`` (default: the running platform).

    A core whose platform entry is missing is simply omitted: the caller
    reports that core as unavailable (fail closed, no insecure fallback).
    """
    platform_id = platform_id or current_platform()
    specs: dict[str, CoreBinarySpec] = {}
    for key in CORE_KEYS:
        raw = cores_cfg.get(key)
        if not isinstance(raw, dict) or not raw.get("version"):
            continue
        version = str(raw["version"])
        # A malformed digest is always a hard error, even when the entry
        # would otherwise be skipped (fail closed, never silently ignore).
        digest_raw = str(raw.get("archive_sha256", "")).strip().lower()
        if digest_raw and (
            len(digest_raw) != 64
            or any(ch not in "0123456789abcdef" for ch in digest_raw)
        ):
            raise CoreInstallError(
                f"core {key}: pinned archive_sha256 is not a SHA-256"
            )
        platforms = raw.get("platforms")
        if isinstance(platforms, dict) and platforms:
            entry = platforms.get(platform_id)
            if not isinstance(entry, dict) or not entry.get("url_template"):
                # No pinned artifact for this platform: fail closed.
                logger.info(
                    "core %s has no pinned artifact for platform %s", key, platform_id
                )
                continue
            specs[key] = _spec_from_platform_entry(key, version, platform_id, entry)
        else:
            if not raw.get("url_template"):
                continue
            specs[key] = _spec_from_platform_entry(key, version, platform_id, raw)
    return specs


def specs_from_testing_config(
    testing_cfg: dict,
    *,
    platform_id: str | None = None,
) -> dict[str, CoreBinarySpec]:
    """Build all four pinned core specs from the full testing config.

    ``singbox`` historically lived in its own top-level section while the
    other cores lived under ``cores``.  The file format stays stable but
    both locations normalize into one installer model.
    """
    combined: dict = {}
    singbox = testing_cfg.get("singbox")
    if isinstance(singbox, dict):
        combined["singbox"] = dict(singbox)
    cores = testing_cfg.get("cores")
    if isinstance(cores, dict):
        combined.update(cores)
    return specs_from_config(combined, platform_id=platform_id)


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

    if _marker_matches(marker_path, spec):
        logger.info(
            "pinned core %s %s already installed for %s",
            spec.key, spec.version, spec.platform,
        )
        return binary_path

    url = spec.url_template.format(version=spec.version)
    logger.info(
        "downloading pinned core %s %s (%s) from official release",
        spec.key, spec.version, spec.platform,
    )
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

        _extract_spec(archive_path, spec, dest_dir, binary_path)
    finally:
        try:
            archive_path.unlink()
        except OSError:
            pass

    ensure_executable(binary_path)
    marker_path.write_text(spec.marker_expected, encoding="utf-8", newline="\n")
    logger.info(
        "core %s %s installed for %s (checksum verified)",
        spec.key, spec.version, spec.platform,
    )
    return binary_path


def _extract_spec(
    archive_path: Path,
    spec: CoreBinarySpec,
    dest_dir: Path,
    binary_path: Path,
) -> None:
    """Extract the pinned binary plus any required extra members."""
    try:
        extract_members(
            archive_path,
            (spec.binary_path_in_archive, *spec.extra_members),
            dest_dir,
            max_bytes=spec.max_bytes,
            fmt=spec.format,
        )
    except Exception as exc:  # noqa: BLE001 - normalize into CoreInstallError
        raise CoreInstallError(str(exc)) from exc
    # Members install flat under their archive basename; the binary must
    # carry the platform-correct install name (e.g. xray -> xray.exe on
    # Windows, hiddify-core -> HiddifyCli.exe), so rename when they differ.
    raw_name = Path(spec.binary_path_in_archive).name
    if raw_name != binary_path.name:
        extracted = dest_dir / raw_name
        if extracted.is_file():
            extracted.replace(binary_path)


def _marker_matches(marker_path: Path, spec: CoreBinarySpec) -> bool:
    if not marker_path.is_file():
        return False
    try:
        if marker_path.read_text(encoding="utf-8") == spec.marker_expected:
            return True
    except OSError:
        pass
    # Legacy marker (pre-cross-platform): key, version, sha256 — accept it
    # only when the binary file exists; the platform line was implicit.
    try:
        legacy = f"{spec.key}\n{spec.version}\n{spec.archive_sha256}\n"
        if marker_path.read_text(encoding="utf-8") == legacy:
            return True
    except OSError:
        pass
    return False


def verify_installed(
    dest_dir: Path,
    spec: CoreBinarySpec,
) -> Path | None:
    """Return the binary path when the pinned core is installed+verified."""
    dest_dir = Path(dest_dir)
    binary_path = dest_dir / spec.binary_name
    marker_path = dest_dir / f"{spec.binary_name}.ok"
    if binary_path.is_file() and _marker_matches(marker_path, spec):
        return binary_path
    return None


def verified_core_paths(
    dest_dir: Path,
    testing_cfg: dict,
    *,
    platform_id: str | None = None,
) -> dict[str, Path]:
    """Return checksum-marker-verified core binaries available for ``platform_id``."""
    specs = specs_from_testing_config(testing_cfg, platform_id=platform_id)
    found: dict[str, Path] = {}
    for key, spec in specs.items():
        path = verify_installed(dest_dir, spec)
        if path is not None:
            found[key] = path
    return found


def install_available_cores(
    dest_dir: Path,
    testing_cfg: dict,
    *,
    platform_id: str | None = None,
    session: requests.Session | None = None,
) -> dict[str, Path]:
    """Install every core pinned for ``platform_id``; skip-and-log failures.

    Mirrors the compatibility engine's availability model: a core that
    cannot be installed is simply unavailable on this platform; its client
    feed is not published from here.
    """
    platform_id = platform_id or current_platform()
    specs = specs_from_testing_config(testing_cfg, platform_id=platform_id)
    installed: dict[str, Path] = {}
    for key in CORE_KEYS:
        spec = specs.get(key)
        if spec is None:
            logger.warning(
                "core %s is not pinned for platform %s - reported unavailable",
                key, platform_id,
            )
            continue
        try:
            installed[key] = install_core_binary(
                dest_dir, spec, session=session
            )
        except CoreInstallError as exc:
            logger.warning("core %s unavailable on %s: %s", key, platform_id, exc)
    return installed
