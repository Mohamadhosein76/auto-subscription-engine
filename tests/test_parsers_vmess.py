"""Tests for the VMess parser (robust base64/JSON handling)."""

from __future__ import annotations

import base64
import json

import pytest

from auto_subscription_engine.core.models import ParseError
from auto_subscription_engine.core.protocols import parse_uri

from conftest import default_vmess_obj, make_vmess_uri

UUID = "12345678-1234-1234-1234-123456789abc"


def test_standard_base64() -> None:
    uri = make_vmess_uri(default_vmess_obj())
    config = parse_uri(uri)
    assert config.protocol == "vmess"
    assert config.host == "vmess.example.com"
    assert config.port == 443
    assert config.identity == UUID
    assert config.name == "Test VMess"
    assert config.params["net"] == "tcp"
    assert config.params["scy"] == "auto"
    assert config.params["aid"] == "0"
    assert config.original_uri == uri


def test_port_as_int() -> None:
    config = parse_uri(make_vmess_uri(default_vmess_obj(port=8443)))
    assert config.port == 8443


def test_port_as_string() -> None:
    config = parse_uri(make_vmess_uri(default_vmess_obj(port="2053")))
    assert config.port == 2053


def test_urlsafe_base64_without_padding() -> None:
    config = parse_uri(make_vmess_uri(default_vmess_obj(), urlsafe=True, pad=False))
    assert config.host == "vmess.example.com"
    assert config.identity == UUID


def test_base64_with_internal_newlines() -> None:
    uri = make_vmess_uri(default_vmess_obj())
    body = uri[len("vmess://") :]
    wrapped = "\n".join(body[i : i + 20] for i in range(0, len(body), 20))
    config = parse_uri("vmess://" + wrapped)
    assert config.host == "vmess.example.com"


def test_invalid_base64_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri("vmess://!!!not-base64-at-all!!!")


def test_decoded_non_json_raises() -> None:
    payload = base64.b64encode(b"hello world").decode()
    with pytest.raises(ParseError):
        parse_uri("vmess://" + payload)


def test_json_array_raises() -> None:
    payload = base64.b64encode(b"[1,2,3]").decode()
    with pytest.raises(ParseError):
        parse_uri("vmess://" + payload)


def test_port_non_numeric_raises() -> None:
    with pytest.raises(ParseError):
        parse_uri(make_vmess_uri(default_vmess_obj(port="abc")))


def test_port_out_of_range_is_parsed_for_validation() -> None:
    config = parse_uri(make_vmess_uri(default_vmess_obj(port=70000)))
    assert config.port == 70000


def test_port_missing_yields_none() -> None:
    obj = default_vmess_obj()
    obj.pop("port")
    config = parse_uri(make_vmess_uri(obj))
    assert config.port is None


def test_missing_add_yields_none_host() -> None:
    obj = default_vmess_obj()
    obj.pop("add")
    config = parse_uri(make_vmess_uri(obj))
    assert config.host is None


def test_missing_id_yields_none_identity() -> None:
    obj = default_vmess_obj()
    obj.pop("id")
    config = parse_uri(make_vmess_uri(obj))
    assert config.identity is None


def test_raw_json_payload_accepted() -> None:
    config = parse_uri("vmess://" + json.dumps(default_vmess_obj()))
    assert config.host == "vmess.example.com"


def test_uri_style_fallback() -> None:
    uri = (
        f"vmess://{UUID}@vmess-uri.example.com:443"
        "?security=tls&encryption=none#uri-style"
    )
    config = parse_uri(uri)
    assert config.protocol == "vmess"
    assert config.host == "vmess-uri.example.com"
    assert config.port == 443
    assert config.identity == UUID
    assert config.name == "uri-style"
    assert config.params["security"] == "tls"


def test_transport_fields_copied_to_params() -> None:
    config = parse_uri(
        make_vmess_uri(
            default_vmess_obj(net="ws", path="/wspath", tls="tls", sni="s.example.com")
        )
    )
    assert config.params["net"] == "ws"
    assert config.params["path"] == "/wspath"
    assert config.params["tls"] == "tls"
    assert config.params["sni"] == "s.example.com"


def test_alternate_host_field_names() -> None:
    config = parse_uri(make_vmess_uri(default_vmess_obj(add="", address="alt.example.com")))
    assert config.host == "alt.example.com"
