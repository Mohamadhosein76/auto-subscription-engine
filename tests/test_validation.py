"""Tests for the structural validation stage."""

from __future__ import annotations

import base64

from auto_subscription_engine.core.models.fingerprint import normalize_config
from auto_subscription_engine.core.protocols import parse_uri
from auto_subscription_engine.core.models.validation import validate_config

from conftest import default_vmess_obj, make_vmess_uri

UUID = "3f6d5b45-91b1-4a7e-8e4e-9c4f0a1b2c3d"


def _check(uri: str):
    return validate_config(normalize_config(parse_uri(uri)))


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def test_valid_public_domain_passes() -> None:
    result = _check(f"vless://{UUID}@public.example.com:443?security=tls#ok")
    assert result.ok
    assert result.reason is None


def test_valid_public_ip_passes() -> None:
    result = _check(f"vless://{UUID}@93.184.216.34:443#ip")
    assert result.ok


def test_valid_ipv6_public_ip_passes() -> None:
    result = _check(f"vless://{UUID}@[2600::1]:443#v6")
    assert result.ok


def test_missing_host_invalid() -> None:
    obj = default_vmess_obj()
    obj.pop("add")
    config = normalize_config(parse_uri(make_vmess_uri(obj)))
    result = validate_config(config)
    assert not result.ok
    assert result.reason == "missing host"


def test_invalid_host_format() -> None:
    result = _check(f"vless://{UUID}@exa mple.com:443")
    assert not result.ok
    assert result.reason == "invalid host format"


def test_localhost_hostname_invalid() -> None:
    result = _check(f"vless://{UUID}@localhost:443")
    assert not result.ok
    assert result.reason == "local or private host"


def test_localhost_fqdn_invalid() -> None:
    result = _check(f"vless://{UUID}@localhost.localdomain:443")
    assert not result.ok


def test_dot_local_suffix_invalid() -> None:
    result = _check(f"vless://{UUID}@printer.local:443")
    assert not result.ok


def test_loopback_ipv4_invalid() -> None:
    result = _check(f"vless://{UUID}@127.0.0.1:8080")
    assert not result.ok


def test_loopback_ipv6_invalid() -> None:
    result = _check(f"vless://{UUID}@[::1]:443")
    assert not result.ok


def test_private_10_invalid() -> None:
    assert not _check(f"vless://{UUID}@10.1.2.3:443").ok


def test_private_172_invalid() -> None:
    assert not _check(f"vless://{UUID}@172.16.0.9:443").ok


def test_private_192_invalid() -> None:
    assert not _check(f"vless://{UUID}@192.168.1.77:443").ok


def test_private_ipv6_invalid() -> None:
    assert not _check(f"vless://{UUID}@[fd00::1]:443").ok


def test_link_local_invalid() -> None:
    assert not _check(f"vless://{UUID}@169.254.169.254:80").ok
    assert not _check(f"vless://{UUID}@[fe80::1]:443").ok


def test_port_zero_invalid() -> None:
    result = _check(make_vmess_uri(default_vmess_obj(port=0)))
    assert not result.ok
    assert result.reason == "port out of range"


def test_port_negative_invalid() -> None:
    result = _check(make_vmess_uri(default_vmess_obj(port=-1)))
    assert not result.ok


def test_port_65536_invalid() -> None:
    result = _check(make_vmess_uri(default_vmess_obj(port=65536)))
    assert not result.ok


def test_port_out_of_range_from_uri() -> None:
    result = _check(f"vless://{UUID}@srv.example.com:70000")
    assert not result.ok
    assert result.reason == "port out of range"


def test_port_boundaries_valid() -> None:
    assert _check(make_vmess_uri(default_vmess_obj(port=1))).ok
    assert _check(make_vmess_uri(default_vmess_obj(port=65535))).ok


def test_missing_port_invalid() -> None:
    result = _check(f"vless://{UUID}@srv.example.com")
    assert not result.ok
    assert result.reason == "missing port"


def test_missing_vless_uuid_invalid() -> None:
    result = _check("vless://srv.example.com:443?security=none")
    assert not result.ok
    assert result.reason == "missing user id"


def test_missing_vmess_id_invalid() -> None:
    obj = default_vmess_obj()
    obj.pop("id")
    result = validate_config(normalize_config(parse_uri(make_vmess_uri(obj))))
    assert not result.ok
    assert result.reason == "missing user id"


def test_missing_trojan_password_invalid() -> None:
    result = _check("trojan://srv.example.com:443#n")
    assert not result.ok
    assert result.reason == "missing password"


def test_missing_hysteria2_password_invalid() -> None:
    result = _check("hysteria2://hy.example.com:443#n")
    assert not result.ok
    assert result.reason == "missing password"


def test_ss_missing_password_invalid() -> None:
    # method present, password empty -> identity has no ":" separator
    userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:").decode().rstrip("=")
    result = _check(f"ss://{userinfo}@ss.example.com:8388")
    assert not result.ok
    assert result.reason == "missing method or password"


def test_ss_valid_passes() -> None:
    userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:pass").decode().rstrip("=")
    result = _check(f"ss://{userinfo}@ss.example.com:8388#s")
    assert result.ok
