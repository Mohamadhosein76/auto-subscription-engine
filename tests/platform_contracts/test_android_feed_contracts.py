"""Android platform feed contract tests (format level; no device claims)."""

from __future__ import annotations

import json

import pytest

from auto_subscription_engine.core.clients.registry import CLIENTS, PLATFORM_FAMILIES
from auto_subscription_engine.core.feeds.engine import _write_platform_feeds


def test_android_clients_are_registered():
    android = {k for k, s in CLIENTS.items() if "android" in s.platforms}
    assert {"v2rayng", "hiddify", "nekobox", "singbox", "mihomo"} <= android


def test_every_client_declares_device_validation_unknown():
    for client, spec in CLIENTS.items():
        assert spec.device_evidence == "device_validation_unknown", (
            f"{client}: no device test exists — the boundary must stay unknown"
        )


def test_platform_families_do_not_mix_device_claims():
    assert set(PLATFORM_FAMILIES) == {"android", "windows"}


def test_android_feed_tree_is_written(tmp_path):
    clients = tmp_path / "clients"
    clients.mkdir()
    (clients / "v2rayng.txt").write_text("vless://a@b:1#x\n", encoding="utf-8", newline="\n")
    import base64

    (clients / "v2rayng_base64.txt").write_text(
        base64.b64encode(b"vless://a@b:1#x\n").decode(), encoding="ascii", newline="\n"
    )
    (clients / "mihomo.yaml").write_text("proxies: []\n", encoding="utf-8", newline="\n")

    counts: dict = {}
    _write_platform_feeds(tmp_path, counts)

    android = tmp_path / "platforms" / "android"
    assert (android / "v2rayng.txt").read_bytes() == (clients / "v2rayng.txt").read_bytes()
    assert (android / "v2rayng_base64.txt").is_file()
    assert (android / "mihomo.yaml").is_file()
    manifest = json.loads((android / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["platform"] == "android"
    assert manifest["clients"]["v2rayng"]["device_evidence"] == "device_validation_unknown"
    assert "device" not in manifest["evidence_boundary"].lower() or "unknown" in manifest["evidence_boundary"]


def test_windows_tree_carries_v2rayn_alias(tmp_path):
    clients = tmp_path / "clients"
    clients.mkdir()
    body = "vless://a@b:1#x\n"
    (clients / "v2rayng.txt").write_text(body, encoding="utf-8", newline="\n")
    import base64

    (clients / "v2rayng_base64.txt").write_text(
        base64.b64encode(body.encode()).decode(), encoding="ascii", newline="\n"
    )
    counts: dict = {}
    _write_platform_feeds(tmp_path, counts)

    windows = tmp_path / "platforms" / "windows"
    assert (windows / "v2rayn.txt").read_bytes() == (clients / "v2rayng.txt").read_bytes()
    manifest = json.loads((windows / "manifest.json").read_text(encoding="utf-8"))
    v2rayn = manifest["clients"]["v2rayn"]
    assert v2rayn["mirrors"] == "clients/v2rayng.txt"
    assert v2rayn["runtime_core"] == "xray"
    assert v2rayn["device_evidence"] == "device_validation_unknown"
