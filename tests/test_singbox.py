"""Tests for the pinned sing-box core: install, checksum, config mapping."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path

import pytest

from auto_subscription_engine.core.models import ParsedConfig
from auto_subscription_engine.core.clients.builders.singbox import (
    allocate_port,
    build_node_config,
    build_outbound,
    write_node_config,
)
from auto_subscription_engine.core.platform.executable import binary_file_name
from auto_subscription_engine.core.clients.install import (
    ChecksumError,
    CoreInstallError,
    CoreBinarySpec,
    install_core_binary,
)


def make_config(protocol: str, uri_params: dict[str, str], identity: str) -> ParsedConfig:
    config = ParsedConfig(
        protocol=protocol,
        host="node.example",
        port=443,
        identity=identity,
        params=uri_params,
        original_uri=f"{protocol}://redacted",
        fingerprint="fp-" + identity[:8],
    )
    return config


# -- config mapping -------------------------------------------------------------


def test_build_outbound_vless_tls_ws():
    config = make_config(
        "vless",
        {"security": "tls", "sni": "sni.example", "type": "ws",
         "path": "/wspath", "host": "ws.example", "flow": "xtls-rprx-vision",
         "alpn": "h2,http/1.1", "fp": "chrome"},
        "b831381d-6324-4d53-ad4f-8cda48b30811",
    )
    outbound = build_outbound(config, resolved_ip="203.0.113.5")
    assert outbound["type"] == "vless"
    assert outbound["server"] == "203.0.113.5"
    assert outbound["server_port"] == 443
    assert outbound["uuid"] == "b831381d-6324-4d53-ad4f-8cda48b30811"
    assert outbound["flow"] == "xtls-rprx-vision"
    assert outbound["tls"]["server_name"] == "sni.example"
    assert outbound["tls"]["alpn"] == ["h2", "http/1.1"]
    assert outbound["tls"]["utls"] == {"enabled": True, "fingerprint": "chrome"}
    assert outbound["transport"] == {
        "type": "ws", "path": "/wspath", "headers": {"Host": "ws.example"}
    }


def test_build_outbound_vless_reality():
    config = make_config(
        "vless",
        {"security": "reality", "pbk": "PUBKEY123", "sid": "abcd",
         "sni": "www.example", "fp": "chrome"},
        "b831381d-6324-4d53-ad4f-8cda48b30811",
    )
    tls = build_outbound(config)["tls"]
    assert tls["reality"] == {"enabled": True, "public_key": "PUBKEY123", "short_id": "abcd"}


def test_build_outbound_vmess_json_style():
    config = make_config(
        "vmess",
        {"aid": "0", "scy": "auto", "net": "ws", "path": "/vm", "host": "v.example",
         "tls": "tls", "sni": "v.example"},
        "b831381d-6324-4d53-ad4f-8cda48b30811",
    )
    outbound = build_outbound(config)
    assert outbound["type"] == "vmess"
    assert outbound["alter_id"] == 0
    assert outbound["security"] == "auto"
    assert outbound["transport"]["type"] == "ws"
    assert outbound["tls"]["enabled"] is True


def test_build_outbound_trojan_with_alpn():
    config = make_config("trojan", {"sni": "t.example", "alpn": "h2,http/1.1"}, "trojan-pass")
    outbound = build_outbound(config)
    assert outbound["type"] == "trojan"
    assert outbound["password"] == "trojan-pass"
    assert outbound["tls"]["enabled"] is True
    assert outbound["tls"]["alpn"] == ["h2", "http/1.1"]


def test_build_outbound_shadowsocks_and_plugin_rejection():
    config = make_config("ss", {}, "aes-256-gcm:secret-password")
    outbound = build_outbound(config)
    assert outbound == {
        "type": "shadowsocks", "tag": "proxy", "server": "node.example",
        "server_port": 443, "method": "aes-256-gcm", "password": "secret-password",
    }
    with pytest.raises(Exception) as excinfo:
        build_outbound(make_config("ss", {"plugin": "obfs-local;obfs=http"}, "m:p"))
    assert "plugin" in str(excinfo.value)


def test_build_outbound_hysteria2_obfs_and_insecure():
    config = make_config(
        "hysteria2",
        {"obfs": "salamander", "obfs-password": "obfspw", "insecure": "1", "sni": "h.example"},
        "hy2-pass",
    )
    outbound = build_outbound(config)
    assert outbound["type"] == "hysteria2"
    assert outbound["obfs"] == {"type": "salamander", "password": "obfspw"}
    assert outbound["tls"]["insecure"] is True


def test_build_outbound_unsupported_transport():
    config = make_config("vless", {"type": "xhttp", "path": "/x"}, "some-uuid")
    with pytest.raises(Exception):
        build_outbound(config)


def test_build_node_config_shape_and_no_dns():
    config = make_config("ss", {}, "aes-256-gcm:pw")
    node_config = build_node_config(config, listen_port=19999, resolved_ip="203.0.113.9")
    assert node_config["inbounds"][0]["type"] == "mixed"
    assert node_config["inbounds"][0]["listen_port"] == 19999
    assert node_config["outbounds"][0]["tag"] == "proxy"
    assert node_config["route"] == {"final": "proxy"}
    assert "dns" not in node_config  # engine resolves itself


def test_write_node_config_permissions(tmp_path):
    config = build_node_config(make_config("ss", {}, "m:p"), listen_port=1)
    path = write_node_config(config, tmp_path)
    mode = stat.S_IMODE(path.stat().st_mode)
    if os.name == "posix":
        assert mode == 0o600
    else:
        # Windows has no POSIX permission bits; the call must at least
        # succeed and the file must stay readable.
        assert mode & 0o400
    parsed = json.loads(path.read_text(encoding="utf-8"))
    assert parsed["outbounds"][0]["method"] == "m"


def test_allocate_port_unique():
    ports = {allocate_port() for _ in range(10)}
    assert len(ports) == 10
    assert all(1024 <= p <= 65535 for p in ports)


# -- pinned core installation -----------------------------------------------------


class FakeResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int):
        for chunk in self._chunks:
            yield chunk

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeSession:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.calls = 0

    def get(self, url, stream=True, timeout=None):
        self.calls += 1
        return FakeResponse(self.chunks)


def make_fake_archive(tmp_path: Path, inner: str, payload: bytes) -> tuple[bytes, Path]:
    archive_path = tmp_path / "fake-core.tar.gz"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=inner)
        info.size = len(payload)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(payload))
    data = buffer.getvalue()
    archive_path.write_bytes(data)
    return data, archive_path


def test_install_core_verifies_checksum_and_is_idempotent(tmp_path):
    payload = b"#!/bin/sh\necho fake-core\n"
    data, _ = make_fake_archive(
        tmp_path, "sing-box-1.14.2-linux-amd64/sing-box", payload
    )
    spec = CoreBinarySpec(
        key="singbox",
        version="1.14.2",
        archive_sha256=hashlib.sha256(data).hexdigest(),
        url_template="https://fake.invalid/core-{version}.tar.gz",
        binary_path_in_archive="sing-box-1.14.2-linux-amd64/sing-box",
        format="tar.gz",
    )
    dest = tmp_path / "core-bin"
    session = FakeSession([data])
    binary = install_core_binary(dest, spec, session=session)
    installed_name = binary_file_name("singbox", spec.platform)
    assert binary.name == installed_name
    assert binary.read_bytes() == payload
    assert os.access(binary, os.X_OK)
    assert (dest / f"{installed_name}.ok").is_file()

    # Second call: marker matches -> no second download.
    install_core_binary(dest, spec, session=session)
    assert session.calls == 1


def test_install_core_rejects_bad_checksum(tmp_path):
    payload = b"fake-binary-content"
    data, _ = make_fake_archive(tmp_path, "x/sing-box", payload)
    spec = CoreBinarySpec(
        key="singbox",
        version="1.14.2",
        archive_sha256="0" * 64,  # wrong on purpose
        url_template="https://fake.invalid/core.tar.gz",
        binary_path_in_archive="x/sing-box",
        format="tar.gz",
    )
    with pytest.raises(ChecksumError):
        install_core_binary(tmp_path / "dest", spec, session=FakeSession([data]))


def test_install_core_missing_member(tmp_path):
    payload = b"fake"
    data, _ = make_fake_archive(tmp_path, "some/other/path", payload)
    spec = CoreBinarySpec(
        key="singbox",
        version="9.9.9",
        archive_sha256=hashlib.sha256(data).hexdigest(),
        url_template="https://fake.invalid/x.tar.gz",
        binary_path_in_archive="missing/sing-box",
        format="tar.gz",
    )
    with pytest.raises(CoreInstallError):
        install_core_binary(tmp_path / "dest", spec, session=FakeSession([data]))
