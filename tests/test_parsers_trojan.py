"""Tests for the Trojan parser."""

from __future__ import annotations

import pytest

from auto_subscription_engine.core.models import ParseError
from auto_subscription_engine.core.protocols import parse_uri


def test_basic() -> None:
    uri = (
        "trojan://s3cret-pass@trojan.example.com:443"
        "?sni=trojan.example.com&type=ws&path=%2Fws#TR%20Node"
    )
    config = parse_uri(uri)
    assert config.protocol == "trojan"
    assert config.host == "trojan.example.com"
    assert config.port == 443
    assert config.identity == "s3cret-pass"
    assert config.name == "TR Node"
    assert config.params["sni"] == "trojan.example.com"
    assert config.params["type"] == "ws"
    assert config.params["path"] == "/ws"
    assert config.original_uri == uri


def test_password_with_encoded_specials() -> None:
    config = parse_uri("trojan://p%40ss%3Aword@trojan.example.com:443#x")
    assert config.identity == "p@ss:word"


def test_ipv6_host() -> None:
    config = parse_uri("trojan://pw@[2001:db8::2]:443#v6")
    assert config.host == "2001:db8::2"


def test_missing_password_yields_none_identity() -> None:
    config = parse_uri("trojan://trojan.example.com:443#n")
    assert config.identity is None


def test_missing_port_yields_none() -> None:
    config = parse_uri("trojan://pw@trojan.example.com#n")
    assert config.port is None


def test_non_numeric_port_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri("trojan://pw@trojan.example.com:44x#n")


def test_no_query_no_fragment() -> None:
    config = parse_uri("trojan://pw@trojan.example.com:443")
    assert config.params == {}
    assert config.name is None


def test_out_of_range_port_parsed_for_validation() -> None:
    config = parse_uri("trojan://pw@trojan.example.com:65540")
    assert config.port == 65540
