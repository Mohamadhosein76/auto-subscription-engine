"""Task 4 tests: security publish guards (min-security, feed outage, cache)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from auto_subscription_engine.core.hardening.publication import (
    DECISION_SKIPPED_MIN_SECURITY,
    DECISION_SKIPPED_SECURITY_UNAVAILABLE,
    MSG_COMMIT_PUBLISH,
    MSG_COMMIT_SECURITY_CACHE,
    GUARD_DECISIONS,
    PublishOptions,
    run_publish,
    snapshot_security_cache,
    security_cache_changed,
)

FAKE_URI = "vless://fake-identity-0@node-0.example:443?security=tls#fake-0"


def _make_output(root: Path, *, security: bool = True,
                 publishable: int = 8, feed_status: str = "fresh") -> Path:
    out = Path(root)
    (out / "countries").mkdir(parents=True, exist_ok=True)
    uris = [
        f"vless://fake-identity-{i}@node-{i}.example:443?security=tls#fake-{i}"
        for i in range(max(publishable, 1))
    ]
    body = "\n".join(uris) + "\n"
    (out / "live_subscription.txt").write_text(body, encoding="utf-8")
    (out / "live_subscription_base64.txt").write_text(
        base64.b64encode(body.encode()).decode("ascii") + "\n", encoding="ascii")
    (out / "best.txt").write_text(body, encoding="utf-8")
    (out / "countries" / "US.txt").write_text(body, encoding="utf-8")
    nodes = []
    for index, uri in enumerate(uris):
        node = {
            "safe_id": f"node_{index:08x}", "protocol": "vless", "status": "live",
            "selected": True, "country_code": "US", "country_name": "United States",
            "resolved_ip": f"93.184.216.{index + 10}", "tcp_latency_ms": 20.0,
            "proxy_latency_ms": 300.0, "success_ratio": 1.0, "score": 90,
        }
        if security:
            node.update({
                "asn": 64512, "as_name": "EXAMPLE-HOSTING", "prefix": "93.184.216.0/24",
                "reputation_hits": [], "dns_status": "ip_literal", "tls_status": "ok",
                "content_integrity_status": "ok", "security_status": "allow",
                "security_risk_score": 0, "security_checks_complete": True,
            })
        nodes.append(node)
    (out / "live_nodes.json").write_text(json.dumps(nodes, indent=2) + "\n", encoding="utf-8")
    stats = {
        "generated_at": "2026-09-29T10:00:00+00:00",
        "configs_received": 10, "final_configs": 8, "candidates_sampled": 8,
        "tcp_tested": 8, "tcp_passed": 4, "proxy_tested": 2, "proxy_live": 1,
        "live_total": publishable, "live_selected": publishable,
        "count_by_country": {"US": publishable},
        "count_by_protocol_live": {"vless": publishable},
        "runtime_seconds": 30.0, "status": "ok",
    }
    if security:
        stats.update({
            "security_checked": publishable,
            "security_publishable": publishable,
            "security_allowed": publishable,
            "security_allowed_with_warnings": 0,
            "security_quarantined": 0,
            "security_blocked": 0,
            "security_feed_status": feed_status,
        })
    (out / "live_stats.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    return out


def _options(output: Path, tmp_path: Path, **overrides) -> PublishOptions:
    defaults = dict(
        output_dir=output,
        public_dir=tmp_path / "public",
        staging_dir=tmp_path / "public.staging",
        min_publishable_nodes=5,
        security_cache_dir=tmp_path / "data" / "security",
    )
    defaults.update(overrides)
    return PublishOptions(**defaults)


def test_new_guard_decisions_are_guards():
    assert DECISION_SKIPPED_MIN_SECURITY in GUARD_DECISIONS
    assert DECISION_SKIPPED_SECURITY_UNAVAILABLE in GUARD_DECISIONS


def test_min_security_guard_skips_publish(tmp_path: Path):
    output = _make_output(tmp_path / "output", publishable=3)
    (tmp_path / "public").mkdir()
    # min_live_nodes lowered so the *distinct* security guard fires first
    result = run_publish(_options(output, tmp_path, min_live_nodes=3))
    assert result.decision == DECISION_SKIPPED_MIN_SECURITY
    assert any("security.min_publishable_nodes" in r for r in result.reasons)
    # previous (empty) public tree untouched; nothing promoted
    assert not (tmp_path / "public" / "subscription.txt").exists()


def test_feed_outage_guard_skips_publish(tmp_path: Path):
    output = _make_output(tmp_path / "output", feed_status="unavailable")
    (tmp_path / "public").mkdir()
    result = run_publish(_options(output, tmp_path))
    assert result.decision == DECISION_SKIPPED_SECURITY_UNAVAILABLE
    assert not (tmp_path / "public" / "subscription.txt").exists()


def test_publish_still_works_without_security_block(tmp_path: Path):
    """Backward compatibility: a pre-Task-4 stats file (no security keys)
    still publishes via the legacy guards."""
    output = _make_output(tmp_path / "output", security=False)
    (tmp_path / "public").mkdir()
    result = run_publish(_options(output, tmp_path))
    assert result.decision == "published"
    assert (tmp_path / "public" / "subscription.txt").is_file()


def test_cache_change_only_recommends_cache_commit(tmp_path: Path):
    output = _make_output(tmp_path / "output", publishable=3)  # guarded skip
    cache_dir = tmp_path / "data" / "security" / "feeds"
    cache_dir.mkdir(parents=True)
    (cache_dir / "spamhaus_drop.json").write_text('{"changed": true}', encoding="utf-8")
    result = run_publish(_options(output, tmp_path, min_live_nodes=3))
    assert result.commit_recommended
    assert result.commit_message == MSG_COMMIT_SECURITY_CACHE
    assert "data/security/" in result.meaningful_changes


def test_snapshot_security_cache_helpers(tmp_path: Path):
    empty = snapshot_security_cache(tmp_path / "missing")
    assert empty == {}
    assert snapshot_security_cache(None) == {}
    cache_dir = tmp_path / "cache"
    (cache_dir / "feeds").mkdir(parents=True)
    (cache_dir / "feeds" / "x.json").write_bytes(b"1")
    snap1 = snapshot_security_cache(cache_dir)
    assert snap1 == {"feeds/x.json": b"1"}
    assert not security_cache_changed(snap1, dict(snap1))
    (cache_dir / "feeds" / "x.json").write_bytes(b"2")
    assert security_cache_changed(snap1, snapshot_security_cache(cache_dir))
