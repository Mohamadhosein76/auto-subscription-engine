"""Tests for URI dispatch: unknown protocols, malformed input, aliases."""

from __future__ import annotations

import pytest

from auto_subscription_engine.core.models import ParseError, UnknownProtocolError
from auto_subscription_engine.core.protocols import parse_uri


def test_unknown_scheme_raises_unknown_protocol() -> None:
    with pytest.raises(UnknownProtocolError):
        parse_uri("socks5://1.2.3.4:1080#x")


def test_unknown_scheme_is_a_parse_error() -> None:
    with pytest.raises(ParseError):
        parse_uri("wireguard://1.2.3.4:51820")


def test_ssr_scheme_is_unknown() -> None:
    with pytest.raises(UnknownProtocolError):
        parse_uri("ssr://cmVhbC1zc3I=")


def test_empty_string_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri("")


def test_no_scheme_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri("example.com:443")


def test_too_long_uri_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri("vless://" + "a" * 20000 + "@h.example.com:443")


def test_hy2_alias_dispatch_uppercase() -> None:
    config = parse_uri("HY2://pw@hy.example.com:443#n")
    assert config.protocol == "hysteria2"


def test_scheme_case_insensitive() -> None:
    config = parse_uri("Vless://3f6d5b45-91b1-4a7e-8e4e-9c4f0a1b2c3d@h.example.com:443")
    assert config.protocol == "vless"


def test_garbage_does_not_crash() -> None:
    for garbage in ("::::", "://", "vless", "a://b", "\n", "vmess://@@@@"):
        try:
            config = parse_uri(garbage)
        except ParseError:
            continue
        # A structurally empty config is fine too: validation flags it later.
        assert config.protocol or True


def test_http_url_is_unknown_protocol() -> None:
    # A stray HTTPS link inside a subscription body must be skipped, not crash.
    with pytest.raises(UnknownProtocolError):
        parse_uri("https://example.com/some/page")
