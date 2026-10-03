"""Tests for fingerprint-based deduplication."""

from __future__ import annotations

import base64

from auto_subscription_engine.core.models.dedup import canonical_order, deduplicate
from auto_subscription_engine.core.models.fingerprint import normalize_config
from auto_subscription_engine.core.protocols import parse_uri

from conftest import default_vmess_obj, make_vmess_uri

UUID = "11111111-2222-3333-4444-555555555555"


def _prep(uris: list[str]):
    return [normalize_config(parse_uri(uri)) for uri in uris]


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def test_exact_duplicate_removed() -> None:
    uri = f"vless://{UUID}@srv.example.com:443?security=tls#dup"
    final, removed = deduplicate(_prep([uri, uri]))
    assert removed == 1
    assert len(final) == 1


def test_same_endpoint_different_names_dedup() -> None:
    a = f"vless://{UUID}@srv.example.com:443?security=tls#name1"
    b = f"vless://{UUID}@srv.example.com:443?security=tls#name2"
    final, removed = deduplicate(_prep([a, b]))
    assert removed == 1
    assert len(final) == 1


def test_different_uuids_same_host_port_kept() -> None:
    a = f"vless://{UUID}@srv.example.com:443#a"
    b = "vless://99999999-8888-7777-6666-555555555555@srv.example.com:443#b"
    final, removed = deduplicate(_prep([a, b]))
    assert removed == 0
    assert len(final) == 2


def test_different_transport_path_kept() -> None:
    a = f"vless://{UUID}@srv.example.com:443?type=ws&path=%2Fa#a"
    b = f"vless://{UUID}@srv.example.com:443?type=ws&path=%2Fb#b"
    final, removed = deduplicate(_prep([a, b]))
    assert removed == 0
    assert len(final) == 2


def test_different_protocols_same_host_port_kept() -> None:
    a = f"vless://{UUID}@srv.example.com:443#a"
    b = "trojan://somepass@srv.example.com:443#b"
    final, removed = deduplicate(_prep([a, b]))
    assert removed == 0
    assert len(final) == 2


def test_ss_different_method_kept() -> None:
    a = f"ss://{_b64('aes-128-gcm:pw')}@ss.example.com:8388"
    b = f"ss://{_b64('aes-256-gcm:pw')}@ss.example.com:8388"
    final, removed = deduplicate(_prep([a, b]))
    assert removed == 0
    assert len(final) == 2


def test_hy2_alias_duplicates_merge() -> None:
    a = "hysteria2://pw@hy.example.com:443?sni=x#one"
    b = "hy2://pw@hy.example.com:443?sni=x#two"
    final, removed = deduplicate(_prep([a, b]))
    assert removed == 1
    assert len(final) == 1


def test_named_survivor_preferred_regardless_of_order() -> None:
    named = f"vless://{UUID}@srv.example.com:443#named"
    unnamed = f"vless://{UUID}@srv.example.com:443"
    final_a, _ = deduplicate(_prep([unnamed, named]))
    final_b, _ = deduplicate(_prep([named, unnamed]))
    assert final_a[0].name == "named"
    assert final_b[0].name == "named"


def test_result_independent_of_input_order() -> None:
    uris = [
        f"vless://{UUID}@srv.example.com:443?a=1#x",
        f"vless://{UUID}@srv.example.com:443?a=1#y",  # duplicate
        "trojan://pw@t.example.com:443#t",
        f"ss://{_b64('aes-256-gcm:pw')}@ss.example.com:8388#s",
        "hysteria2://pw@hy.example.com:443#h",
        "hy2://pw@hy.example.com:443#h2",  # duplicate of the hysteria2 entry
    ]
    final_a, removed_a = deduplicate(_prep(uris))
    final_b, removed_b = deduplicate(_prep(list(reversed(uris))))
    assert removed_a == removed_b == 2
    assert canonical_order(final_a) == canonical_order(final_b)


def test_canonical_order_is_sorted() -> None:
    vmess_uri = make_vmess_uri(
        default_vmess_obj(add="m.example.com", port="443", id=UUID, ps="vm")
    )
    uris = [
        vmess_uri,
        "trojan://pw@t.example.com:443#t",
        f"vless://{UUID}@v.example.com:443#v",
        "ss://YWVzLTI1Ni1nY206cHc=@s.example.com:8388#s",
        "hysteria2://pw@h.example.com:443#h",
    ]
    final = canonical_order(_prep(uris))
    protocols = [config.protocol for config in final]
    assert protocols == sorted(protocols)


def test_empty_input() -> None:
    final, removed = deduplicate([])
    assert final == []
    assert removed == 0
