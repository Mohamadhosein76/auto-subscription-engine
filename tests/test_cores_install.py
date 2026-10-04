"""Pinned multi-core installer tests (offline, fake archives)."""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from auto_subscription_engine.core.clients.install import (
    ChecksumError,
    CoreBinarySpec,
    CoreInstallError,
    install_core_binary,
    specs_from_config,
    verify_installed,
)
from auto_subscription_engine.core.platform.executable import binary_file_name


def make_tar_gz(path: Path, member: str, payload: bytes) -> None:
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo(member)
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))


def make_zip(path: Path, member: str, payload: bytes) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(member, payload)


def make_gz(path: Path, payload: bytes) -> None:
    with gzip.open(path, "wb") as stream:
        stream.write(payload)


def fake_session(archive_path: Path):
    """Minimal session stand-in serving one local archive."""
    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size):
            data = archive_path.read_bytes()
            for offset in range(0, len(data), chunk_size):
                yield data[offset:offset + chunk_size]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class FakeSession:
        def get(self, url, stream=False, timeout=None):
            return FakeResponse()

    return FakeSession()


def make_spec(tmp_path: Path, fmt: str, archive: Path, member: str) -> CoreBinarySpec:
    import hashlib

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return CoreBinarySpec(
        key="mihomo" if fmt == "gz" else "xray" if fmt == "zip" else "hiddify",
        version="9.9.9",
        archive_sha256=digest,
        url_template="https://example.invalid/download/v{version}/archive",
        binary_path_in_archive=member,
        format=fmt,
    )


def test_tar_gz_install_extracts_single_binary(tmp_path):
    payload = b"#!/bin/sh\necho fake-binary\n"
    archive = tmp_path / "a.tar.gz"
    make_tar_gz(archive, "pkg-9.9.9/binary", payload)
    spec = make_spec(tmp_path, "tar.gz", archive, "pkg-9.9.9/binary")
    dest = tmp_path / "core-bin"
    binary = install_core_binary(dest, spec, session=fake_session(archive))
    installed_name = binary_file_name(spec.key, spec.platform)
    assert binary.is_file()
    assert binary.read_bytes() == payload
    assert binary.name == installed_name
    assert (dest / f"{installed_name}.ok").is_file()


def test_zip_install(tmp_path):
    payload = b"PK-fake-binary"
    archive = tmp_path / "a.zip"
    make_zip(archive, "xray", payload)
    spec = make_spec(tmp_path, "zip", archive, "xray")
    binary = install_core_binary(tmp_path / "out", spec, session=fake_session(archive))
    assert binary.read_bytes() == payload


def test_gz_install(tmp_path):
    payload = b"GZ-fake-binary"
    archive = tmp_path / "a.gz"
    make_gz(archive, payload)
    spec = make_spec(tmp_path, "gz", archive, "mihomo-linux-amd64")
    binary = install_core_binary(tmp_path / "out", spec, session=fake_session(archive))
    assert binary.read_bytes() == payload
    assert binary.name == binary_file_name("mihomo", spec.platform)


def test_checksum_mismatch_refuses(tmp_path):
    archive = tmp_path / "a.tar.gz"
    make_tar_gz(archive, "x/b", b"data")
    spec = make_spec(tmp_path, "tar.gz", archive, "x/b")
    bad = CoreBinarySpec(**{**spec.__dict__, "archive_sha256": "0" * 64})
    with pytest.raises(ChecksumError):
        install_core_binary(tmp_path / "out", bad, session=fake_session(archive))
    assert not (tmp_path / "out" / binary_file_name("hiddify", bad.platform)).exists()


def test_max_archive_size_enforced(tmp_path):
    archive = tmp_path / "a.zip"
    make_zip(archive, "xray", b"x" * 1024)
    spec = make_spec(tmp_path, "zip", archive, "xray")
    tiny = CoreBinarySpec(**{**spec.__dict__, "max_bytes": 16})
    with pytest.raises(CoreInstallError):
        install_core_binary(tmp_path / "out", tiny, session=fake_session(archive))


def test_install_is_idempotent(tmp_path):
    archive = tmp_path / "a.tar.gz"
    make_tar_gz(archive, "x/b", b"payload-1")
    spec = make_spec(tmp_path, "tar.gz", archive, "x/b")
    dest = tmp_path / "out"
    installed_name = binary_file_name(spec.key, spec.platform)
    first = install_core_binary(dest, spec, session=fake_session(archive))
    marker = (dest / f"{installed_name}.ok").read_text(encoding="utf-8")
    # a second call with the SAME marker must skip the download entirely
    class ExplodingSession:
        def get(self, *args, **kwargs):
            raise AssertionError("download must not happen on idempotent install")

    second = install_core_binary(dest, spec, session=ExplodingSession())
    assert first == second
    assert (dest / f"{installed_name}.ok").read_text(encoding="utf-8") == marker


def test_verify_installed(tmp_path):
    archive = tmp_path / "a.tar.gz"
    make_tar_gz(archive, "x/b", b"data")
    spec = make_spec(tmp_path, "tar.gz", archive, "x/b")
    dest = tmp_path / "out"
    installed_name = binary_file_name(spec.key, spec.platform)
    assert verify_installed(dest, spec) is None
    install_core_binary(dest, spec, session=fake_session(archive))
    assert verify_installed(dest, spec) == dest / installed_name


def test_specs_from_config_validates_digest(tmp_path):
    with pytest.raises(CoreInstallError):
        specs_from_config({"xray": {"version": "1", "archive_sha256": "short"}})
    specs = specs_from_config({
        "xray": {
            "version": "26.6.27",
            "archive_sha256": "a" * 64,
            "url_template": "https://x/v{version}",
            "binary_path_in_archive": "xray",
            "format": "zip",
        }
    })
    assert specs["xray"].binary_name == binary_file_name("xray", specs["xray"].platform)
