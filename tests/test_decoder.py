"""Tests for subscription content decoding (plain / multiline / base64)."""

from __future__ import annotations

import base64

from auto_subscription_engine.core.ingestion.text import extract_uri_lines

from conftest import load_fixture


def test_plain_multiline() -> None:
    text = "vless://u@h1.example.com:443?x=1#a\n\ntrojan://p@h2.example.com:443#b\n"
    assert extract_uri_lines(text) == [
        "vless://u@h1.example.com:443?x=1#a",
        "trojan://p@h2.example.com:443#b",
    ]


def test_plain_lines_without_scheme_are_dropped() -> None:
    text = "hello world\nvless://u@h.example.com:443\nnot a uri\n\n"
    assert extract_uri_lines(text) == ["vless://u@h.example.com:443"]


def test_base64_subscription() -> None:
    lines = extract_uri_lines(load_fixture("base64_subscription.txt"))
    assert len(lines) == 3
    assert lines[0].startswith("vless://")
    assert lines[1].startswith("trojan://")
    assert lines[2].startswith("ss://")


def test_base64_urlsafe_without_padding() -> None:
    payload = "vless://u@h.example.com:443#n\n"
    encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    assert extract_uri_lines(encoded) == ["vless://u@h.example.com:443#n"]


def test_base64_wrapped_across_lines() -> None:
    payload = "vless://u@h.example.com:443#n\ntrojan://p@h2.example.com:443#m\n"
    encoded = base64.b64encode(payload.encode()).decode()
    wrapped = "\n".join(encoded[i : i + 16] for i in range(0, len(encoded), 16))
    assert extract_uri_lines(wrapped) == [
        "vless://u@h.example.com:443#n",
        "trojan://p@h2.example.com:443#m",
    ]


def test_empty_input() -> None:
    assert extract_uri_lines("") == []
    assert extract_uri_lines("   \n \n") == []


def test_non_base64_garbage_without_scheme() -> None:
    assert extract_uri_lines("this is not base64 !!! and not a uri") == []


def test_plain_scheme_wins_over_base64_interpretation() -> None:
    # A body that already contains a scheme delimiter is treated as plain
    # text even when other lines look base64-ish.
    text = "dmxlc3M6LyBhYmNkZWZnaA\nvless://u@h.example.com:443#real"
    assert extract_uri_lines(text) == ["vless://u@h.example.com:443#real"]


def test_mixed_fixture_uri_inventory() -> None:
    lines = extract_uri_lines(load_fixture("mixed_subscription.txt"))
    assert len(lines) == 14
    assert any(line.startswith("vmess://") for line in lines)
    assert any(line.startswith("hy2://") for line in lines)
