"""Stage 1 regression contract for stable public subscription paths.

These paths are user-facing API surface. Refactors may change implementation,
but must not silently delete or rename the existing feeds.
"""

from __future__ import annotations

import base64
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC = REPO_ROOT / "public"
README = REPO_ROOT / "README.md"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "build-subscription.yml"

LEGACY_PUBLIC_FILES = (
    "subscription.txt",
    "subscription_base64.txt",
    "best.txt",
    "status.json",
    "live_nodes.json",
    "live_stats.json",
    "clients/universal.txt",
    "clients/universal_base64.txt",
    "clients/v2rayng.txt",
    "clients/v2rayng_base64.txt",
    "clients/hiddify.txt",
    "clients/hiddify_base64.txt",
    "clients/nekobox.txt",
    "clients/nekobox_base64.txt",
    "clients/mihomo.yaml",
    "networks/mobile-safe.txt",
    "networks/mobile-safe_base64.txt",
)


def test_legacy_public_files_remain_present():
    missing = [name for name in LEGACY_PUBLIC_FILES if not (PUBLIC / name).is_file()]
    assert not missing, f"legacy public contract files disappeared: {missing}"


def test_plain_and_base64_legacy_feeds_match():
    pairs = (
        ("subscription.txt", "subscription_base64.txt"),
        ("clients/universal.txt", "clients/universal_base64.txt"),
        ("clients/v2rayng.txt", "clients/v2rayng_base64.txt"),
        ("clients/hiddify.txt", "clients/hiddify_base64.txt"),
        ("clients/nekobox.txt", "clients/nekobox_base64.txt"),
        ("networks/mobile-safe.txt", "networks/mobile-safe_base64.txt"),
    )
    for plain_name, b64_name in pairs:
        plain = (PUBLIC / plain_name).read_bytes()
        encoded = (PUBLIC / b64_name).read_text(encoding="ascii").strip()
        assert base64.b64decode(encoded, validate=True) == plain, plain_name


def test_readme_keeps_documented_raw_urls():
    text = README.read_text(encoding="utf-8")
    base = "https://raw.githubusercontent.com/Mohamadhosein76/auto-subscription-engine/main/public/"
    for name in (
        "subscription.txt",
        "subscription_base64.txt",
        "clients/v2rayng.txt",
        "clients/hiddify.txt",
        "clients/nekobox.txt",
        "clients/mihomo.yaml",
    ):
        assert base + name in text, name


def test_publish_workflow_still_targets_main_and_public_tree():
    parsed = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert "build" in parsed["jobs"]
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "git add public data/history.json data/discovery.json data/ip_history.json data/security" in text
    assert "git push origin HEAD:main" in text
    assert "verify-publish --public-dir public" in text
