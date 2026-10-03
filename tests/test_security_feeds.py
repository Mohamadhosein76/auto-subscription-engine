"""Task 4 tests: reputation feeds, parsing, persistent cache, refresh policy.

All tests are fully offline: feed bodies are strings/bytes, the downloader
is injected, and time is controlled via explicit ``now`` arguments.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from auto_subscription_engine.core.security.feedcache import (
    FeedCache,
    FeedRecord,
    build_record,
    entries_digest,
)
from auto_subscription_engine.core.security.feeds import (
    SOURCE_FEODO_RECOMMENDED,
    SOURCE_SPAMHAUS_ASNDROP,
    SOURCE_SPAMHAUS_DROP,
    SOURCE_SPAMHAUS_DROPV6,
    FeedUnavailableError,
    build_feed_view,
    ip_in_drop_networks,
    parse_feodo_recommended,
    parse_spamhaus_asndrop,
    parse_spamhaus_drop,
    refresh_feeds,
)

NOW = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_parse_spamhaus_drop_ipv4():
    body = (
        "# DROP/EDIT Data as of 29/09/2026\n"
        "# comments ignored\n"
        "1.2.3.0/24 ; S1234\n"
        "5.6.7.0/24 ; S5678\n"
        "\n"
        "not-a-network ; S0000\n"
        "9.9.9.0/24 ; S9999\n"
    )
    entries = parse_spamhaus_drop(body)
    assert entries == ["1.2.3.0/24", "5.6.7.0/24", "9.9.9.0/24"]


def test_parse_spamhaus_drop_ipv6():
    body = "# DROPv6\n2001:db8::/32 ; S1\n2001:bad::/48 ; S2\nbroken::/zz ; S3\n"
    entries = parse_spamhaus_drop(body)
    assert "2001:db8::/32" in entries
    assert "2001:bad::/48" in entries
    assert len(entries) == 2


def test_parse_spamhaus_asndrop_formats():
    body = (
        "# ASN-DROP\n"
        "AS64496 ; S1\n"
        "AS64500 | evil-network\n"
        "ASnonsense ; S2\n"
        "64497 ; S3\n"  # missing AS prefix -> skipped
    )
    entries = parse_spamhaus_asndrop(body)
    assert entries == [64496, 64500]


def test_parse_feodo_recommended_json():
    payload = [
        {"ip_address": "5.6.7.8", "malware": "testbot", "first_seen": "2026-09-29"},
        {"ip_address": "not-an-ip"},
        {"other": 1},
    ]
    entries = parse_feodo_recommended(json.dumps(payload))
    assert entries == ["5.6.7.8"]


def test_parse_feodo_recommended_txt_fallback():
    body = "# recommended blocklist\n5.6.7.8\n9.9.9.9\nbroken\n"
    entries = parse_feodo_recommended(body)
    assert entries == ["5.6.7.8", "9.9.9.9"]


def test_parse_feodo_recommended_broken_json_is_empty():
    assert parse_feodo_recommended("{definitely not json") == []


# ---------------------------------------------------------------------------
# Cache: atomic write, verification, corruption recovery
# ---------------------------------------------------------------------------


def _make_record(source: str, entries: list, *, now=NOW) -> FeedRecord:
    return build_record(
        source,
        f"https://example.com/{source}.txt",
        entries,
        b"raw-content",
        refresh_interval_hours=24,
        max_age_hours=96,
        now=now,
    )


def test_feed_cache_roundtrip(tmp_path: Path):
    cache = FeedCache(tmp_path)
    record = _make_record(SOURCE_SPAMHAUS_DROP, ["1.2.3.0/24"])
    cache.save(record)
    loaded = cache.load(SOURCE_SPAMHAUS_DROP)
    assert loaded is not None
    assert loaded.entries == ["1.2.3.0/24"]
    assert loaded.fetched_at == record.fetched_at
    assert loaded.attribution and "Spamhaus" in loaded.attribution


def test_feed_cache_detects_hash_mismatch(tmp_path: Path):
    cache = FeedCache(tmp_path)
    cache.save(_make_record(SOURCE_SPAMHAUS_DROP, ["1.2.3.0/24"]))
    path = cache.path_for(SOURCE_SPAMHAUS_DROP)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["entries"] = ["4.4.4.0/24"]  # tampered payload, hash now stale
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert cache.load(SOURCE_SPAMHAUS_DROP) is None


def test_feed_cache_corruption_recovery(tmp_path: Path):
    cache = FeedCache(tmp_path)
    cache.path_for(SOURCE_SPAMHAUS_DROP).write_text("{corrupt json", encoding="utf-8")
    assert cache.load(SOURCE_SPAMHAUS_DROP) is None  # miss, never a crash


def test_feed_cache_entry_count_mismatch(tmp_path: Path):
    cache = FeedCache(tmp_path)
    cache.save(_make_record(SOURCE_SPAMHAUS_DROP, ["1.2.3.0/24"]))
    path = cache.path_for(SOURCE_SPAMHAUS_DROP)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["entries"] = []
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert cache.load(SOURCE_SPAMHAUS_DROP) is None


def test_feed_cache_write_is_atomic_deterministic(tmp_path: Path):
    cache = FeedCache(tmp_path)
    record = _make_record(SOURCE_SPAMHAUS_DROP, ["9.9.9.0/24"])
    cache.save(record)
    first = cache.path_for(SOURCE_SPAMHAUS_DROP).read_bytes()
    cache.save(_make_record(SOURCE_SPAMHAUS_DROP, ["9.9.9.0/24"]))
    second = cache.path_for(SOURCE_SPAMHAUS_DROP).read_bytes()
    assert first == second  # deterministic serialization
    leftovers = [p for p in tmp_path.iterdir() if p.suffix == ".tmp"]
    assert leftovers == []  # no temp files left behind


def test_feed_cache_is_fresh_and_usable_windows():
    fresh = _make_record(SOURCE_SPAMHAUS_DROP, [])
    assert FeedCache.is_fresh(fresh, 24, NOW)
    assert FeedCache.is_usable(fresh, 96, NOW)
    stale = _make_record(SOURCE_SPAMHAUS_DROP, [], now=NOW - timedelta(hours=48))
    assert not FeedCache.is_fresh(stale, 24, NOW)
    assert FeedCache.is_usable(stale, 96, NOW)
    ancient = _make_record(SOURCE_SPAMHAUS_DROP, [], now=NOW - timedelta(hours=200))
    assert not FeedCache.is_fresh(ancient, 24, NOW)
    assert not FeedCache.is_usable(ancient, 96, NOW)
    assert not FeedCache.is_fresh(None, 24, NOW)
    assert entries_digest(["a"]) == entries_digest(["a"])


# ---------------------------------------------------------------------------
# Refresh policy: rate guard, stale fallback, hard outage
# ---------------------------------------------------------------------------


FEED_CFG = {
    "spamhaus_drop": "https://feeds.example/drop.txt",
    "spamhaus_dropv6": "https://feeds.example/dropv6.txt",
    "spamhaus_asndrop": "https://feeds.example/asndrop.txt",
    "feodo_recommended": "https://feeds.example/feodo.json",
    "refresh_interval_hours": 24,
    "max_age_hours": 96,
    "timeout_seconds": 5,
    "retries": 1,
    "max_bytes": 1024 * 1024,
}

BODIES = {
    FEED_CFG["spamhaus_drop"]: b"# drop\n1.2.3.0/24 ; S1\n",
    FEED_CFG["spamhaus_dropv6"]: b"# dropv6\n2001:db8::/32 ; S1\n",
    FEED_CFG["spamhaus_asndrop"]: b"# asndrop\nAS64496 ; S1\n",
    FEED_CFG["feodo_recommended"]: b'[{"ip_address": "5.6.7.8"}]',
}


def _downloader_recording(calls: list):
    def _download(url):
        calls.append(url)
        return BODIES[url]

    return _download


def _downloader_failing(url):
    raise ConnectionError("feed service unreachable")


def test_refresh_downloads_when_no_cache(tmp_path: Path):
    cache = FeedCache(tmp_path)
    calls: list = []
    records, statuses = refresh_feeds(
        FEED_CFG, cache, now=NOW, downloader=_downloader_recording(calls)
    )
    assert statuses == {s: "downloaded" for s in records}
    assert len(calls) == 4
    assert records[SOURCE_SPAMHAUS_ASNDROP].entries == [64496]


def test_refresh_rate_guard_no_redownload(tmp_path: Path):
    cache = FeedCache(tmp_path)
    first_calls: list = []
    refresh_feeds(FEED_CFG, cache, now=NOW, downloader=_downloader_recording(first_calls))
    second_calls: list = []
    records, statuses = refresh_feeds(
        FEED_CFG, cache, now=NOW + timedelta(minutes=30), downloader=_downloader_recording(second_calls)
    )
    assert second_calls == []  # the hourly run must not re-download
    assert set(statuses.values()) == {"fresh"}


def test_refresh_failure_with_valid_cache_serves_cache(tmp_path: Path):
    cache = FeedCache(tmp_path)
    refresh_feeds(FEED_CFG, cache, now=NOW, downloader=_downloader_recording([]))
    # Two days later the feed is stale (past 24h refresh) but within the
    # 96h usable window - a failed download must serve the cache.
    records, statuses = refresh_feeds(
        FEED_CFG,
        cache,
        now=NOW + timedelta(hours=48),
        downloader=_downloader_failing,
    )
    assert set(statuses.values()) == {"cached"}
    assert records[SOURCE_SPAMHAUS_DROP].entries == ["1.2.3.0/24"]


def test_refresh_failure_with_stale_cache_raises(tmp_path: Path):
    cache = FeedCache(tmp_path)
    refresh_feeds(FEED_CFG, cache, now=NOW, downloader=_downloader_recording([]))
    # 200h old: beyond max_age_hours=96 and no download possible.
    with pytest.raises(FeedUnavailableError):
        refresh_feeds(
            FEED_CFG,
            cache,
            now=NOW + timedelta(hours=200),
            downloader=_downloader_failing,
        )


def test_refresh_no_cache_and_failure_raises(tmp_path: Path):
    cache = FeedCache(tmp_path)
    with pytest.raises(FeedUnavailableError):
        refresh_feeds(FEED_CFG, cache, now=NOW, downloader=_downloader_failing)


def test_refresh_corrupt_cache_and_failure_raises(tmp_path: Path):
    cache = FeedCache(tmp_path)
    cache.path_for(SOURCE_SPAMHAUS_DROP).write_text("junk{", encoding="utf-8")
    with pytest.raises(FeedUnavailableError):
        refresh_feeds(FEED_CFG, cache, now=NOW, downloader=_downloader_failing)


# ---------------------------------------------------------------------------
# Feed view / membership
# ---------------------------------------------------------------------------


def test_build_feed_view_and_ip_membership(tmp_path: Path):
    cache = FeedCache(tmp_path / "feeds")
    records, _ = refresh_feeds(FEED_CFG, cache, now=NOW, downloader=_downloader_recording([]))
    view = build_feed_view(records)
    assert ip_in_drop_networks("1.2.3.4", view.drop_networks)
    assert not ip_in_drop_networks("8.8.8.8", view.drop_networks)
    assert not ip_in_drop_networks("not-an-ip", view.drop_networks)
    assert 64496 in view.asndrop_asns
    assert "5.6.7.8" in view.feodo_ips


def test_drop_membership_ipv6():
    from auto_subscription_engine.core.security.feeds import parse_spamhaus_drop
    import ipaddress

    networks = [ipaddress.ip_network("2001:db8::/32")]
    assert ip_in_drop_networks("2001:db8::1", networks)
    assert not ip_in_drop_networks("2001:db9::1", networks)
