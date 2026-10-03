"""Tests for the VLESS parser."""

from __future__ import annotations

import pytest

from auto_subscription_engine.core.models import ParseError
from auto_subscription_engine.core.protocols import parse_uri

UUID = "3f6d5b45-91b1-4a7e-8e4e-9c4f0a1b2c3d"


def test_basic() -> None:
    uri = (
        f"vless://{UUID}@server.example.com:443?encryption=none&security=tls"
        "&sni=cdn.example.com&type=ws&path=%2Fpath#Node%20One"
    )
    config = parse_uri(uri)
    assert config.protocol == "vless"
    assert config.host == "server.example.com"
    assert config.port == 443
    assert config.identity == UUID
    assert config.name == "Node One"
    assert config.params["type"] == "ws"
    assert config.params["path"] == "/path"
    assert config.params["security"] == "tls"
    assert config.params["encryption"] == "none"
    assert config.original_uri == uri


def test_uppercase_scheme() -> None:
    config = parse_uri(f"VLESS://{UUID}@server.example.com:443")
    assert config.protocol == "vless"


def test_ipv6_bracketed_host() -> None:
    config = parse_uri(f"vless://{UUID}@[2001:db8::1]:443?security=tls#v6")
    assert config.host == "2001:db8::1"
    assert config.port == 443


def test_missing_uuid_yields_none_identity() -> None:
    config = parse_uri("vless://server.example.com:443?security=none")
    assert config.identity is None
    assert config.host == "server.example.com"
    assert config.port == 443


def test_missing_port_yields_none() -> None:
    config = parse_uri(f"vless://{UUID}@server.example.com")
    assert config.port is None


def test_out_of_range_port_is_parsed_for_validation() -> None:
    config = parse_uri(f"vless://{UUID}@server.example.com:70000")
    assert config.port == 70000


def test_non_numeric_port_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri(f"vless://{UUID}@server.example.com:abc")


def test_missing_scheme_delimiter_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri("server.example.com:443")


def test_empty_payload_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri("vless://")


def test_encoded_specials_in_userinfo() -> None:
    config = parse_uri("vless://uuid-with%3Acolon@server.example.com:443")
    assert config.identity == "uuid-with:colon"


def test_unicode_fragment_name() -> None:
    config = parse_uri(f"vless://{UUID}@server.example.com:443#%D8%AA%D8%B3%D8%AA")
    assert config.name == "تست"


def test_empty_query_and_fragment() -> None:
    config = parse_uri(f"vless://{UUID}@server.example.com:443")
    assert config.params == {}
    assert config.name is None
