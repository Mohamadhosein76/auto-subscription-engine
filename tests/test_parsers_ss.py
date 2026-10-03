"""Tests for the Shadowsocks (SS) parser: SIP002 and legacy formats."""

from __future__ import annotations

import base64

import pytest

from auto_subscription_engine.core.models import ParseError
from auto_subscription_engine.core.protocols import parse_uri


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def b64url_nopad(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def test_sip002_base64_userinfo_with_padding() -> None:
    uri = f"ss://{b64('aes-256-gcm:testpass')}@ss.example.com:8388#Node"
    config = parse_uri(uri)
    assert config.protocol == "ss"
    assert config.host == "ss.example.com"
    assert config.port == 8388
    assert config.identity == "aes-256-gcm:testpass"
    assert config.name == "Node"
    assert config.original_uri == uri


def test_sip002_base64url_without_padding() -> None:
    uri = f"ss://{b64url_nopad('chacha20-ietf-poly1305:pass')}@ss.example.com:8388#N"
    config = parse_uri(uri)
    assert config.identity == "chacha20-ietf-poly1305:pass"
    assert config.port == 8388


def test_sip002_plain_userinfo() -> None:
    uri = "ss://aes-128-gcm:plainpass@ss.example.com:8388#plain"
    config = parse_uri(uri)
    assert config.identity == "aes-128-gcm:plainpass"
    assert config.host == "ss.example.com"
    assert config.port == 8388


def test_sip002_percent_encoded_userinfo() -> None:
    uri = "ss://aes-128-gcm%3Ap%40ss@ss.example.com:8388#enc"
    config = parse_uri(uri)
    assert config.identity == "aes-128-gcm:p@ss"


def test_sip002_with_path_and_plugin() -> None:
    userinfo = b64url_nopad("aes-256-gcm:pass")
    uri = (
        f"ss://{userinfo}@ss.example.com:8388/"
        "?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#plug"
    )
    config = parse_uri(uri)
    assert config.host == "ss.example.com"
    assert config.port == 8388
    assert config.params["plugin"] == "obfs-local;obfs=http;obfs-host=cdn.example.com"


def test_legacy_full_base64() -> None:
    payload = b64("aes-128-gcm:legacypass@legacy.example.com:1234")
    uri = f"ss://{payload}#legacy"
    config = parse_uri(uri)
    assert config.host == "legacy.example.com"
    assert config.port == 1234
    assert config.identity == "aes-128-gcm:legacypass"
    assert config.name == "legacy"


def test_legacy_with_standard_base64_slash_chars() -> None:
    # A legacy payload whose standard base64 form contains "/" characters.
    # Pure ASCII never produces "/" in base64, but a UTF-8 password (here
    # "pÿw") does — and the "/" must not be mistaken for a URI path.
    inner = "aes-256-gcm:pÿw@legacy2.example.com:5678"
    encoded = b64(inner)
    assert "/" in encoded
    config = parse_uri(f"ss://{encoded}")
    assert config.host == "legacy2.example.com"
    assert config.port == 5678
    assert config.identity == "aes-256-gcm:pÿw"


def test_bad_legacy_base64_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri("ss://!!not-base64!!#x")


def test_userinfo_without_separator_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri(f"ss://{b64('noseparator')}@ss.example.com:8388#n")


def test_missing_method_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri(f"ss://{b64(':passwordonly')}@ss.example.com:8388#n")


def test_missing_port_yields_none() -> None:
    config = parse_uri(f"ss://{b64url_nopad('aes-256-gcm:pass')}@ss.example.com")
    assert config.port is None


def test_empty_password_leads_to_method_only_identity() -> None:
    config = parse_uri(f"ss://{b64url_nopad('aes-256-gcm:')}@ss.example.com:8388")
    assert config.identity == "aes-256-gcm"


def test_ipv6_host_sip002() -> None:
    config = parse_uri(f"ss://{b64url_nopad('aes-256-gcm:pw')}@[2001:db8::3]:8388")
    assert config.host == "2001:db8::3"
    assert config.port == 8388
