"""Task 4 tests: pre-publish security verification (verify-security)."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from auto_subscription_engine.core.protocols import parse_uri
from auto_subscription_engine.core.utils.identity import config_safe_id
from auto_subscription_engine.core.security.feedcache import FeedCache, build_record
from auto_subscription_engine.core.security.verify import verify_security_outputs

NOW = datetime.now(timezone.utc)
TESTING_CONFIG = Path(__file__).parent.parent / "config" / "testing.yaml"

URI_A = "vless://11111111-2222-3333-4444-555555555555@93.184.216.34:443?security=tls&type=tcp#a"
URI_B = "trojan://pw@b.example:443?security=tls#b"


@pytest.fixture()
def good_output(tmp_path: Path) -> Path:
    output = tmp_path / "output"
    (output / "countries").mkdir(parents=True)
    feeds = tmp_path / "data" / "security" / "feeds"
    feeds.mkdir(parents=True)
    cache = FeedCache(feeds)
    for source, url, entries in (
        ("spamhaus_drop", "drop.txt", ["1.2.3.0/24"]),
        ("spamhaus_dropv6", "dropv6.txt", ["2001:db8::/32"]),
        ("spamhaus_asndrop", "asndrop.json", [64496]),
        ("feodo_recommended", "ipblocklist_recommended.json", ["5.6.7.8"]),
    ):
        cache.save(build_record(
            source, f"https://www.example/{url}", entries, b"data",
            refresh_interval_hours=24, max_age_hours=96, now=NOW - timedelta(hours=2),
        ))

    config_a = parse_uri(URI_A)
    nodes = [{
        "safe_id": config_safe_id(config_a),
        "protocol": "vless",
        "status": "live",
        "selected": True,
        "country_code": "US",
        "country_name": "United States",
        "resolved_ip": "93.184.216.34",
        "tcp_latency_ms": 20.0,
        "proxy_latency_ms": 300.0,
        "success_ratio": 1.0,
        "score": 90,
        "asn": 64512,
        "as_name": "EXAMPLE-HOSTING",
        "prefix": "93.184.216.0/24",
        "reputation_hits": [],
        "dns_status": "ip_literal",
        "tls_status": "ok",
        "content_integrity_status": "ok",
        "security_status": "allow",
        "security_risk_score": 0,
        "security_checks_complete": True,
    }]
    (output / "live_nodes.json").write_text(json.dumps(nodes, indent=2) + "\n", encoding="utf-8")
    body = URI_A + "\n"
    (output / "live_subscription.txt").write_text(body, encoding="utf-8")
    (output / "live_subscription_base64.txt").write_text(
        base64.b64encode(body.encode()).decode() + "\n", encoding="ascii"
    )
    (output / "best.txt").write_text(body, encoding="utf-8")
    (output / "countries" / "US.txt").write_text(body, encoding="utf-8")
    stats = {
        "live_total": 1,
        "live_selected": 1,
        "security_checked": 1,
        "security_publishable": 1,
        "security_allowed": 1,
        "security_allowed_with_warnings": 0,
        "security_quarantined": 0,
        "security_blocked": 0,
        "cloudflare_nodes_blocked": 0,
        "security_feed_status": "fresh",
        "security_feed_age": 2.0,
    }
    (output / "live_stats.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    (output / "security_diagnostics.json").write_text(
        json.dumps({"note": "credential-free diagnostics; no URIs, UUIDs or passwords",
                    "nodes": []}, indent=2) + "\n",
        encoding="utf-8",
    )
    return output


def test_valid_outputs_pass(good_output: Path):
    assert verify_security_outputs(good_output, TESTING_CONFIG) == []


def test_missing_security_block_is_flagged(tmp_path: Path):
    output = tmp_path / "output"
    output.mkdir()
    (output / "live_stats.json").write_text("{}", encoding="utf-8")
    problems = verify_security_outputs(output, TESTING_CONFIG)
    assert any("no security block" in p for p in problems)


def test_blocked_stats_shape_mismatch_flagged(good_output: Path):
    stats = json.loads((good_output / "live_stats.json").read_text())
    stats["security_publishable"] = 5  # but subscription has 1 line
    (good_output / "live_stats.json").write_text(json.dumps(stats), encoding="utf-8")
    problems = verify_security_outputs(good_output, TESTING_CONFIG)
    assert any("security_publishable (5)" in p for p in problems)


def test_quarantined_metadata_is_visible_not_published(good_output: Path):
    """A quarantined node may appear in metadata (transparency) - verify
    only checks the published *lines* stay clean via counts/mapping."""
    nodes = json.loads((good_output / "live_nodes.json").read_text())
    nodes.append(dict(nodes[0], safe_id="node_deadbeefcafe", security_status="quarantine",
                      selected=False))
    (good_output / "live_nodes.json").write_text(json.dumps(nodes), encoding="utf-8")
    # metadata transparency is fine as long as counts stay consistent
    problems = verify_security_outputs(good_output, TESTING_CONFIG)
    assert [p for p in problems if "security_status" in p] == []


def test_uri_leak_in_metadata_is_flagged(good_output: Path):
    nodes = json.loads((good_output / "live_nodes.json").read_text())
    nodes[0]["note"] = URI_A  # someone leaked a URI into metadata
    (good_output / "live_nodes.json").write_text(json.dumps(nodes), encoding="utf-8")
    problems = verify_security_outputs(good_output, TESTING_CONFIG)
    assert any("contains a proxy URI" in p for p in problems)


def test_uuid_leak_in_metadata_is_flagged(good_output: Path):
    nodes = json.loads((good_output / "live_nodes.json").read_text())
    nodes[0]["note"] = "id 12345678-1234-1234-1234-123456789abc"
    (good_output / "live_nodes.json").write_text(json.dumps(nodes), encoding="utf-8")
    problems = verify_security_outputs(good_output, TESTING_CONFIG)
    assert any("contains a UUID" in p for p in problems)


def test_invalid_security_status_is_flagged(good_output: Path):
    nodes = json.loads((good_output / "live_nodes.json").read_text())
    nodes[0]["security_status"] = "probably_fine"
    (good_output / "live_nodes.json").write_text(json.dumps(nodes), encoding="utf-8")
    problems = verify_security_outputs(good_output, TESTING_CONFIG)
    assert any("invalid security_status" in p for p in problems)


def test_bad_risk_score_is_flagged(good_output: Path):
    nodes = json.loads((good_output / "live_nodes.json").read_text())
    nodes[0]["security_risk_score"] = 500
    (good_output / "live_nodes.json").write_text(json.dumps(nodes), encoding="utf-8")
    problems = verify_security_outputs(good_output, TESTING_CONFIG)
    assert any("invalid security_risk_score" in p for p in problems)


def test_incomplete_published_node_flagged_only_under_strict_policy(good_output: Path, tmp_path: Path):
    """With quarantine_on_incomplete=false the honest-flagged publish is
    allowed; with true it must be an error (node should be quarantined)."""
    import yaml as _yaml
    nodes = json.loads((good_output / "live_nodes.json").read_text())
    nodes[0]["security_checks_complete"] = False
    (good_output / "live_nodes.json").write_text(json.dumps(nodes), encoding="utf-8")
    # default policy: allowed (honest flag, warnings in metadata)
    assert verify_security_outputs(good_output, TESTING_CONFIG) == []
    # strict policy: hard error
    cfg = tmp_path / "strict.yaml"
    base = _yaml.safe_load(TESTING_CONFIG.read_text())
    base["security"]["policy"]["quarantine_on_incomplete"] = True
    cfg.write_text(_yaml.safe_dump(base))
    problems = verify_security_outputs(good_output, cfg)
    assert any("incomplete security checks" in p for p in problems)


def test_base64_mismatch_is_flagged(good_output: Path):
    (good_output / "live_subscription_base64.txt").write_text("AAAA\n", encoding="ascii")
    problems = verify_security_outputs(good_output, TESTING_CONFIG)
    assert any("base64" in p for p in problems)


def test_missing_or_corrupt_feed_cache_is_flagged(good_output: Path):
    feeds = good_output.parent / "data" / "security" / "feeds"
    (feeds / "spamhaus_drop.json").write_text("{corrupt", encoding="utf-8")
    problems = verify_security_outputs(good_output, TESTING_CONFIG)
    assert any("spamhaus_drop" in p for p in problems)


def test_stale_feed_cache_is_flagged(good_output: Path, tmp_path: Path):
    feeds = good_output.parent / "data" / "security" / "feeds"
    cache = FeedCache(feeds)
    cache.save(build_record(
        "spamhaus_drop", "https://www.example/drop.txt", ["1.2.3.0/24"], b"d",
        refresh_interval_hours=24, max_age_hours=96,
        now=NOW - timedelta(hours=200),  # beyond max_age 96h
    ))
    problems = verify_security_outputs(good_output, TESTING_CONFIG)
    assert any("stale" in p for p in problems)


def test_future_feed_timestamp_is_flagged(good_output: Path):
    feeds = good_output.parent / "data" / "security" / "feeds"
    cache = FeedCache(feeds)
    cache.save(build_record(
        "spamhaus_drop", "https://www.example/drop.txt", ["1.2.3.0/24"], b"d",
        refresh_interval_hours=24, max_age_hours=96,
        now=NOW + timedelta(hours=48),
    ))
    problems = verify_security_outputs(good_output, TESTING_CONFIG)
    assert any("future" in p for p in problems)


def test_missing_diagnostics_is_flagged(good_output: Path):
    (good_output / "security_diagnostics.json").unlink()
    problems = verify_security_outputs(good_output, TESTING_CONFIG)
    assert any("security_diagnostics.json" in p for p in problems)
