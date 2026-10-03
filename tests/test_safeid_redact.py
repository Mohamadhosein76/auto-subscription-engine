"""Tests for safe ids and credential redaction (privacy guarantees)."""

from __future__ import annotations

import logging

from auto_subscription_engine.core.models import ParsedConfig
from auto_subscription_engine.core.utils.redaction import node_log, redact_stderr, redact_text
from auto_subscription_engine.core.utils.identity import config_safe_id, describe_node, safe_id

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
URI = f"vless://{UUID}@secret-host.example:443?security=tls&sni=secret-host.example&flow=xtls-rprx-vision#MySecretNode"


def make_config() -> ParsedConfig:
    config = ParsedConfig(
        protocol="vless",
        host="secret-host.example",
        port=443,
        identity=UUID,
        name="MySecretNode",
        original_uri=URI,
        fingerprint="f" * 64,
    )
    return config


def test_safe_id_is_stable_and_short():
    first = safe_id("abc123")
    second = safe_id("abc123")
    assert first == second
    assert first.startswith("node_")
    hex_part = first[len("node_"):]
    assert len(hex_part) == 12
    int(hex_part, 16)  # valid hex


def test_safe_id_differs_per_fingerprint():
    assert safe_id("a") != safe_id("b")


def test_describe_node_never_leaks_identity():
    description = describe_node(make_config())
    assert UUID not in description
    assert URI not in description
    assert "MySecretNode" not in description
    assert "secret-host.example:443" in description


def test_config_safe_id_uses_fingerprint():
    config = make_config()
    assert config_safe_id(config) == safe_id("f" * 64)


def test_redact_text_removes_uuid_and_userinfo():
    redacted = redact_text(URI)
    assert UUID not in redacted
    assert "[REDACTED]" in redacted
    assert redacted.startswith("vless://[REDACTED]@")
    assert "secret-host.example:443" in redacted


def test_redact_text_removes_key_value_secrets():
    text = "config loaded: password=hunter2 uuid=" + UUID + " ok"
    redacted = redact_text(text)
    assert "hunter2" not in redacted
    assert UUID not in redacted


def test_redact_text_removes_long_blobs():
    blob = "aB3" + "x9" * 30
    assert blob not in redact_text(f"key {blob} end")


def test_redact_text_keeps_ordinary_text():
    text = "node passed: endpoint=demo.example:443 latency 123.4 ms"
    assert redact_text(text) == text


def test_redact_stderr_handles_bytes_and_truncates():
    noisy = ("x" * 5000 + " password=topsecretvalue1234567890").encode("utf-8")
    cleaned = redact_stderr(noisy)
    assert len(cleaned) <= 400
    assert "topsecretvalue1234567890" not in cleaned


def test_node_log_uses_safe_id_and_redaction(caplog):
    logger = logging.getLogger("test-node-log")
    with caplog.at_level(logging.DEBUG, logger="test-node-log"):
        node_log(logger, logging.INFO, make_config(), f"probe failed uri={URI}")
    text = caplog.text
    assert UUID not in text
    assert URI not in text
    assert "node_" in text
