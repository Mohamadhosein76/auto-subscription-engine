"""Android platform feed contract tests (format level; no device claims).

Runs the REAL feed stage against a minimal post-compat fixture, then
asserts the platform gate: fresh qualifying evidence only, no stale
nodes, honest evidence boundary in the manifest.
"""

from __future__ import annotations

import json
from pathlib import Path

from feed_fixture import VLESS_A, STALE_VLESS, build_feed_output

from auto_subscription_engine.core.clients.registry import CLIENTS, PLATFORM_FAMILIES
from auto_subscription_engine.core.feeds import FeedOptions, run_feed_stage


def _run(tmp_path: Path) -> Path:
    out = build_feed_output(tmp_path)
    run_feed_stage(FeedOptions(output_dir=out, config_path=Path("config/feeds.yaml")))
    return out


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
    out = _run(tmp_path)
    android = out / "platforms" / "android"
    assert (android / "v2rayng.txt").is_file()
    assert (android / "hiddify.txt").is_file()
    manifest = json.loads((android / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["platform"] == "android"
    assert manifest["device_validation"] == "manual_observation_only"
    assert manifest["operator_validation"] == "unknown"
    hiddify = manifest["clients"]["hiddify"]
    assert hiddify["runtime_core"] == "hiddify"
    assert hiddify["device_evidence"] == "device_validation_unknown"
    assert "fresh" in hiddify["selection_policy"]


def test_stale_evidence_never_enters_platform_feed(tmp_path):
    out = _run(tmp_path)
    android = out / "platforms" / "android"
    for artifact in ("v2rayng.txt", "hiddify.txt", "nekobox.txt"):
        body = (android / artifact).read_text(encoding="utf-8")
        assert STALE_VLESS not in body, f"stale node leaked into {artifact}"
        assert VLESS_A in body, f"fresh node missing from {artifact}"


def test_platform_feed_is_not_larger_than_client_feed(tmp_path):
    out = _run(tmp_path)
    client_body = (out / "clients" / "hiddify.txt").read_text(encoding="utf-8")
    platform_body = (out / "platforms" / "android" / "hiddify.txt").read_text(encoding="utf-8")
    client_lines = {x for x in client_body.splitlines() if x}
    platform_lines = {x for x in platform_body.splitlines() if x}
    assert platform_lines <= client_lines, "platform feed must be a qualified subset"
