"""Tests for the Hysteria2 parser (incl. the hy2:// alias)."""

from __future__ import annotations

import pytest

from auto_subscription_engine.core.models import ParseError
from auto_subscription_engine.core.protocols import parse_uri


def test_basic() -> None:
    uri = (
        "hysteria2://hy-pass@hy.example.com:36712/"
        "?sni=hy.example.com&insecure=1#HY%20Node"
    )
    config = parse_uri(uri)
    assert config.protocol == "hysteria2"
    assert config.host == "hy.example.com"
    assert config.port == 36712
    assert config.identity == "hy-pass"
    assert config.name == "HY Node"
    assert config.params["sni"] == "hy.example.com"
    assert config.params["insecure"] == "1"
    assert config.original_uri == uri


def test_hy2_alias_normalizes_protocol() -> None:
    config = parse_uri("hy2://hy-pass@hy.example.com:36712?sni=hy.example.com#alias")
    assert config.protocol == "hysteria2"
    assert config.port == 36712


def test_obfs_params() -> None:
    uri = (
        "hysteria2://pw@hy.example.com:443/"
        "?obfs=salamander&obfs-password=obfspw&sni=x.example.com#o"
    )
    config = parse_uri(uri)
    assert config.params["obfs"] == "salamander"
    assert config.params["obfs-password"] == "obfspw"


def test_default_port_is_443() -> None:
    config = parse_uri("hysteria2://pw@hy.example.com/?sni=hy.example.com#np")
    assert config.port == 443


def test_missing_password_yields_none_identity() -> None:
    config = parse_uri("hysteria2://hy.example.com:443#n")
    assert config.identity is None


def test_non_numeric_port_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri("hysteria2://pw@hy.example.com:44x#n")


def test_ipv6_host() -> None:
    config = parse_uri("hysteria2://pw@[2001:db8::4]:8443#v6")
    assert config.host == "2001:db8::4"
    assert config.port == 8443


def test_query_without_slash() -> None:
    config = parse_uri("hy2://pw@hy.example.com:1234?sni=a#b")
    assert config.params["sni"] == "a"
    assert config.name == "b"
