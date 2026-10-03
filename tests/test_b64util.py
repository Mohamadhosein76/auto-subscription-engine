"""Tests for the robust base64 helper."""

from __future__ import annotations

import base64

from auto_subscription_engine.core.utils.base64 import robust_b64decode


def test_standard_base64() -> None:
    assert robust_b64decode("aGVsbG8=") == "hello"


def test_missing_padding_is_added() -> None:
    assert robust_b64decode("aGVsbG8") == "hello"


def test_urlsafe_alphabet() -> None:
    raw = "abc-def_ghi+123?"
    encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    assert robust_b64decode(encoded) == raw


def test_whitespace_and_newlines_are_stripped() -> None:
    raw = "aGVs\n bG8=\n"
    assert robust_b64decode(raw) == "hello"


def test_invalid_characters_return_none() -> None:
    assert robust_b64decode("!!!not base64!!!") is None


def test_plain_text_with_colon_return_none() -> None:
    # Plain method:password strings must not be mis-decoded as base64.
    assert robust_b64decode("aes-256-gcm:password") is None


def test_non_utf8_bytes_return_none() -> None:
    encoded = base64.b64encode(b"\xff\xfe\xfd").decode()
    assert robust_b64decode(encoded) is None


def test_empty_input_returns_none() -> None:
    assert robust_b64decode("") is None
    assert robust_b64decode("   \n ") is None


def test_decodes_a_real_subscription_blob() -> None:
    payload = "vless://u@h.example.com:443#n\ntrojan://p@h2.example.com:443#m\n"
    encoded = base64.b64encode(payload.encode()).decode()
    assert robust_b64decode(encoded) == payload
