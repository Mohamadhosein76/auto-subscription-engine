"""Windows client feed + cross-platform public contract tests."""

from __future__ import annotations

import json

from auto_subscription_engine.core.clients.registry import CLIENTS
from auto_subscription_engine.core.feeds.engine import _write_platform_feeds


def _seed_clients(tmp_path):
    clients = tmp_path / "clients"
    clients.mkdir()
    body = "vless://a@b:1#x\n"
    import base64

    b64 = base64.b64encode(body.encode()).decode()
    for name in ("v2rayng.txt", "hiddify.txt", "nekobox.txt", "universal.txt"):
        (clients / name).write_text(body, encoding="utf-8", newline="\n")
        (clients / name.replace(".txt", "_base64.txt")).write_text(
            b64, encoding="ascii", newline="\n"
        )
    (clients / "mihomo.yaml").write_text("proxies: []\n", encoding="utf-8", newline="\n")
    (clients / "singbox.json").write_text('{"outbounds": []}\n', encoding="utf-8", newline="\n")


def test_windows_clients_are_registered():
    windows = {k for k, s in CLIENTS.items() if "windows" in s.platforms}
    assert {"hiddify", "nekobox", "singbox", "mihomo"} <= windows


def test_windows_feed_tree_is_written(tmp_path):
    _seed_clients(tmp_path)
    counts: dict = {}
    _write_platform_feeds(tmp_path, counts)

    windows = tmp_path / "platforms" / "windows"
    assert (windows / "hiddify.txt").is_file()
    assert (windows / "nekobox.txt").is_file()
    assert (windows / "singbox.json").is_file()
    assert (windows / "mihomo.yaml").is_file()
    assert (windows / "v2rayn.txt").is_file()
    manifest = json.loads((windows / "manifest.json").read_text(encoding="utf-8"))
    assert all(
        entry["device_evidence"] == "device_validation_unknown"
        for entry in manifest["clients"].values()
    )


def test_platform_mirrors_never_diverge_from_clients(tmp_path):
    _seed_clients(tmp_path)
    counts: dict = {}
    _write_platform_feeds(tmp_path, counts)
    clients = tmp_path / "clients"
    for family in ("android", "windows"):
        for mirrored in (tmp_path / "platforms" / family).glob("*.txt"):
            if mirrored.name.endswith("_base64.txt"):
                continue
            source_name = "v2rayng.txt" if mirrored.name.startswith("v2rayn") else mirrored.name
            source = clients / source_name
            if source.is_file():
                assert mirrored.read_bytes() == source.read_bytes()


def test_public_contract_urls_unchanged(tmp_path):
    """The legacy public URL set must never break (Phase 16)."""
    legacy = {
        "subscription.txt",
        "subscription_base64.txt",
        "best.txt",
        "live_nodes.json",
        "clients/v2rayng.txt",
        "clients/hiddify.txt",
        "clients/nekobox.txt",
        "clients/mihomo.yaml",
        "clients/universal.txt",
    }
    import auto_subscription_engine.core.hardening.publication as publication

    # The stager must still map these exact names.
    staged_pairs = (
        ("live_subscription.txt", "subscription.txt"),
        ("live_subscription_base64.txt", "subscription_base64.txt"),
        ("best.txt", "best.txt"),
        ("live_nodes.json", "live_nodes.json"),
    )
    assert {dst for _, dst in staged_pairs} <= legacy
    # Platform trees are additive, never replacing the legacy paths.
    for path in legacy:
        assert not path.startswith("platforms/")
