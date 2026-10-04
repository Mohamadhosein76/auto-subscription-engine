"""Safe archive extraction tests (zip / tar.gz / tar.xz / gz + traversal)."""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile

import pytest

from auto_subscription_engine.core.platform.archive import (
    ArchiveError,
    extract_member,
    extract_members,
    validate_member_name,
)


def make_zip(path, name, payload):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(name, payload)


def make_tar(path, name, payload, mode="w:gz"):
    members = name if isinstance(name, list) else [name]
    payloads = payload if isinstance(payload, list) else [payload]
    with tarfile.open(path, mode) as t:
        for member_name, member_payload in zip(members, payloads):
            data = io.BytesIO(member_payload)
            info = tarfile.TarInfo(member_name)
            info.size = len(member_payload)
            t.addfile(info, data)


def test_zip_member(tmp_path):
    archive = tmp_path / "a.zip"
    make_zip(archive, "dir/core.exe", b"zip-payload")
    dest = tmp_path / "core.exe"
    extract_member(archive, "dir/core.exe", dest, max_bytes=1024, fmt="zip")
    assert dest.read_bytes() == b"zip-payload"


def test_tar_gz_member(tmp_path):
    archive = tmp_path / "a.tar.gz"
    make_tar(archive, "pkg-1.0/core", b"tar-payload")
    dest = tmp_path / "core"
    extract_member(archive, "pkg-1.0/core", dest, max_bytes=1024, fmt="tar.gz")
    assert dest.read_bytes() == b"tar-payload"


def test_tar_xz_member(tmp_path):
    archive = tmp_path / "a.tar.xz"
    make_tar(archive, "pkg-1.0/core", b"xz-payload", mode="w:xz")
    dest = tmp_path / "core"
    extract_member(archive, "pkg-1.0/core", dest, max_bytes=1024, fmt="tar.xz")
    assert dest.read_bytes() == b"xz-payload"


def test_gz_single_member(tmp_path):
    archive = tmp_path / "a.gz"
    with gzip.open(archive, "wb") as f:
        f.write(b"gz-payload")
    dest = tmp_path / "core"
    extract_member(archive, "core", dest, max_bytes=1024, fmt="gz")
    assert dest.read_bytes() == b"gz-payload"


@pytest.mark.parametrize(
    "name",
    [
        "../evil",
        "../../etc/passwd",
        "/absolute/path",
        "C:\\Windows\\evil.exe",
        "C:/evil",
        "..\\..\\evil",
        "",
    ],
)
def test_traversal_names_rejected(name):
    with pytest.raises(ArchiveError):
        validate_member_name(name)


def test_missing_member_raises(tmp_path):
    archive = tmp_path / "a.zip"
    make_zip(archive, "real.exe", b"x")
    with pytest.raises(ArchiveError):
        extract_member(archive, "not-there.exe", tmp_path / "out", max_bytes=10, fmt="zip")


def test_member_size_cap(tmp_path):
    archive = tmp_path / "a.zip"
    make_zip(archive, "big.exe", b"x" * 4096)
    with pytest.raises(ArchiveError):
        extract_member(archive, "big.exe", tmp_path / "out", max_bytes=1024, fmt="zip")


def test_extract_members_flat(tmp_path):
    archive = tmp_path / "multi.tar.gz"
    make_tar(archive, ["pkg/core-cli", "pkg/helper.dll"], [b"main", b"dll"])
    written = extract_members(
        archive, ("pkg/core-cli", "pkg/helper.dll"), tmp_path, max_bytes=1024, fmt="tar.gz"
    )
    assert sorted(w.name for w in written) == ["core-cli", "helper.dll"]
