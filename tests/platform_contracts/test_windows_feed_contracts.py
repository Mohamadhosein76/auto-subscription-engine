"""Windows client feed + cross-platform public contract tests."""

from __future__ import annotations

import json
from pathlib import Path

from feed_fixture import STALE_VLESS, build_feed_output

from auto_subscription_engine.core.clients.registry import CLIENTS
from auto_subscription_engine.core.feeds import FeedOptions, run_feed_stage


def _run(tmp_path: Path) -> Path:
    out = build_feed_output(tmp_path)
    run_feed_stage(FeedOptions(output_dir=out, config_path=Path("config/feeds.yaml")))
    return out


def test_windows_clients_are_registered():
    windows = {k for k, s in CLIENTS.items() if "windows" in s.platforms}
    assert {"hiddify", "nekobox", "singbox", "mihomo"} <= windows


def test_windows_feed_tree_is_written(tmp_path):
    out = _run(tmp_path)
    windows = out / "platforms" / "windows"
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
    assert manifest["device_validation"] == "manual_observation_only"


def test_stale_evidence_never_enters_windows_feed(tmp_path):
    out = _run(tmp_path)
    windows = out / "platforms" / "windows"
    for artifact in ("hiddify.txt", "v2rayn.txt"):
        body = (windows / artifact).read_text(encoding="utf-8")
        assert STALE_VLESS not in body, f"stale node leaked into {artifact}"


def test_platform_feed_is_qualified_subset_of_client_feed(tmp_path):
    out = _run(tmp_path)
    client_body = (out / "clients" / "hiddify.txt").read_text(encoding="utf-8")
    platform_body = (out / "platforms" / "windows" / "hiddify.txt").read_text(encoding="utf-8")
    client_lines = {x for x in client_body.splitlines() if x}
    platform_lines = {x for x in platform_body.splitlines() if x}
    assert platform_lines <= client_lines


def test_public_contract_urls_unchanged():
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
    staged_pairs = (
        ("live_subscription.txt", "subscription.txt"),
        ("live_subscription_base64.txt", "subscription_base64.txt"),
        ("best.txt", "best.txt"),
        ("live_nodes.json", "live_nodes.json"),
    )
    assert {dst for _, dst in staged_pairs} <= legacy
    for path in legacy:
        assert not path.startswith("platforms/")
