"""Tests for normalization and logical fingerprint computation."""

from __future__ import annotations

import base64

from auto_subscription_engine.core.models.fingerprint import compute_fingerprint, normalize_config
from auto_subscription_engine.core.protocols import parse_uri

from conftest import default_vmess_obj, make_vmess_uri

UUID = "11111111-2222-3333-4444-555555555555"


def _fp(uri: str) -> str:
    return normalize_config(parse_uri(uri)).fingerprint


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def test_display_name_not_in_fingerprint() -> None:
    a = _fp(f"vless://{UUID}@srv.example.com:443?security=tls&type=ws&path=%2Fws#A")
    b = _fp(f"vless://{UUID}@srv.example.com:443?security=tls&type=ws&path=%2Fws#B")
    assert a == b


def test_different_uuid_different_fingerprint() -> None:
    a = _fp(f"vless://{UUID}@srv.example.com:443")
    b = _fp("vless://99999999-8888-7777-6666-555555555555@srv.example.com:443")
    assert a != b


def test_different_port_different_fingerprint() -> None:
    a = _fp(f"vless://{UUID}@srv.example.com:443")
    b = _fp(f"vless://{UUID}@srv.example.com:8443")
    assert a != b


def test_different_ws_path_different_fingerprint() -> None:
    a = _fp(f"vless://{UUID}@srv.example.com:443?type=ws&path=%2Fa")
    b = _fp(f"vless://{UUID}@srv.example.com:443?type=ws&path=%2Fb")
    assert a != b


def test_different_transport_type_different_fingerprint() -> None:
    a = _fp(f"vless://{UUID}@srv.example.com:443?type=ws&path=%2Fws")
    b = _fp(f"vless://{UUID}@srv.example.com:443?type=tcp")
    assert a != b


def test_missing_security_equals_none() -> None:
    a = _fp(f"vless://{UUID}@srv.example.com:443")
    b = _fp(f"vless://{UUID}@srv.example.com:443?security=none")
    assert a == b


def test_hy2_scheme_alias_same_fingerprint() -> None:
    a = _fp("hysteria2://pw@hy.example.com:443?sni=x#n")
    b = _fp("hy2://pw@hy.example.com:443?sni=x#m")
    assert a == b


def test_uuid_case_insensitive_fingerprint() -> None:
    a = _fp(f"vless://{UUID}@srv.example.com:443")
    b = _fp(f"vless://{UUID.upper()}@srv.example.com:443")
    assert a == b


def test_host_case_and_trailing_dot_normalized() -> None:
    a = _fp(f"vless://{UUID}@SRV.EXAMPLE.COM:443")
    b = _fp(f"vless://{UUID}@srv.example.com.:443")
    assert a == b


def test_vmess_display_name_not_in_fingerprint() -> None:
    a = _fp(make_vmess_uri(default_vmess_obj(ps="one")))
    b = _fp(make_vmess_uri(default_vmess_obj(ps="two")))
    assert a == b


def test_vmess_tls_empty_equals_none() -> None:
    a = _fp(make_vmess_uri(default_vmess_obj(tls="")))
    b = _fp(make_vmess_uri(default_vmess_obj(tls="none")))
    assert a == b


def test_vmess_aid_and_scy_not_in_fingerprint() -> None:
    a = _fp(make_vmess_uri(default_vmess_obj(aid="0", scy="auto")))
    b = _fp(make_vmess_uri(default_vmess_obj(aid="64", scy="none")))
    assert a == b


def test_alpn_order_insensitive() -> None:
    a = _fp(f"vless://{UUID}@srv.example.com:443?security=tls&alpn=h2,http%2F1.1")
    b = _fp(f"vless://{UUID}@srv.example.com:443?security=tls&alpn=http%2F1.1,h2")
    assert a == b


def test_ss_method_case_insensitive_fingerprint() -> None:
    a = _fp(f"ss://{_b64('AES-256-GCM:pw')}@ss.example.com:8388")
    b = _fp(f"ss://{_b64('aes-256-gcm:pw')}@ss.example.com:8388")
    assert a == b


def test_ss_plugin_changes_fingerprint() -> None:
    a = _fp(f"ss://{_b64('aes-256-gcm:pw')}@ss.example.com:8388")
    b = _fp(f"ss://{_b64('aes-256-gcm:pw')}@ss.example.com:8388?plugin=obfs-local")
    assert a != b


def test_different_protocol_same_host_port_not_merged() -> None:
    a = _fp(f"vless://{UUID}@srv.example.com:443")
    b = _fp("trojan://somepass@srv.example.com:443")
    assert a != b


def test_reality_pbk_changes_fingerprint() -> None:
    a = _fp(f"vless://{UUID}@srv.example.com:443?security=reality&pbk=KEY1")
    b = _fp(f"vless://{UUID}@srv.example.com:443?security=reality&pbk=KEY2")
    assert a != b


def test_fingerprint_is_sha256_hex() -> None:
    fingerprint = _fp(f"vless://{UUID}@srv.example.com:443")
    assert len(fingerprint) == 64
    int(fingerprint, 16)  # must be valid hex


def test_compute_fingerprint_stable() -> None:
    config = parse_uri(f"vless://{UUID}@srv.example.com:443?security=tls")
    assert compute_fingerprint(config) == compute_fingerprint(config)
