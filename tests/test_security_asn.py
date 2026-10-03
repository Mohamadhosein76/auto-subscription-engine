"""Task 4 tests: ASN intelligence (Team Cymru primary, RIPEstat fallback).

Fully offline: the whois query is injected, HTTP fallback is monkeypatched
and time is controlled.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import auto_subscription_engine.core.security.asnmap as asnmap
from auto_subscription_engine.core.security.asnmap import (
    AsnCache,
    AsnInfo,
    _parse_cymru_response,
    resolve_asn_map,
)

NOW = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)

ASN_CFG = {
    "whois_host": "whois.cymru.com",
    "whois_port": 43,
    "fallback_url": "https://stat.ripe.example/network-info",
    "timeout_seconds": 5,
    "retries": 1,
    "concurrency": 4,
    "cache_ttl_hours": 336,
    "max_cache_entries": 100,
    "max_lookups_per_run": 100,
}


# ---------------------------------------------------------------------------
# Cymru response parsing
# ---------------------------------------------------------------------------


def test_parse_cymru_response_verbose_rows():
    body = (
        "Bulk mode; whois.cymru.com [2026-09-29 12:00:00 +0000]\n"
        "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n"
        "15169 | 8.8.8.8 | 8.8.8.0/24 | US | arin | 1992-12-01 | GOOGLE, US\n"
        "13335 | 1.1.1.1 | 1.1.1.0/24 | US | arin | na | CLOUDFLARENET (bogus test string)\n"
        "NA | 9.9.9.9 | NA | NA | NA | NA | NA\n"
    )
    results = _parse_cymru_response(body)
    assert results["8.8.8.8"].asn == 15169
    assert results["8.8.8.8"].prefix == "8.8.8.0/24"
    assert "GOOGLE" in (results["8.8.8.8"].as_name or "")
    assert results["9.9.9.9"].asn is None
    assert results["9.9.9.9"].source == "cymru_whois"


def test_parse_cymru_response_malformed_lines_ignored():
    assert _parse_cymru_response("garbage\n\n|||\nAS1 | 8.8.8.8 | too | few") == {}
    body = "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n1 | 1.2.3.4 | 1.2.3.0/24 | US | arin | na | TEST\n"
    assert _parse_cymru_response(body)["1.2.3.4"].asn == 1


# ---------------------------------------------------------------------------
# Persistent per-IP cache
# ---------------------------------------------------------------------------


def test_asn_cache_roundtrip_and_prune(tmp_path: Path):
    cache = AsnCache(tmp_path / "asn_cache.json")
    entries = {
        "8.8.8.8": {"asn": 15169, "as_name": "GOOGLE", "prefix": "8.8.8.0/24",
                    "source": "cymru_whois", "looked_up_at": NOW.isoformat()},
    }
    cache.save(entries)
    assert cache.load() == entries
    # prune respects TTL
    pruned = AsnCache.prune(entries, ttl_hours=1, max_entries=100, now=NOW)
    assert pruned == entries
    expired = AsnCache.prune(entries, ttl_hours=1, max_entries=100,
                             now=NOW + timedelta(hours=2))
    assert expired == {}


def test_asn_cache_max_entries_cap(tmp_path: Path):
    entries = {
        f"10.0.0.{i}": {"asn": i, "looked_up_at": (NOW - timedelta(hours=i)).isoformat()}
        for i in range(5)
    }
    pruned = AsnCache.prune(entries, ttl_hours=1000, max_entries=3, now=NOW)
    assert len(pruned) == 3
    # the *most recently* looked-up entries survive
    assert "10.0.0.0" in pruned and "10.0.0.4" not in pruned


def test_asn_cache_corruption_recovery(tmp_path: Path):
    path = tmp_path / "asn_cache.json"
    path.write_text("{broken", encoding="utf-8")
    assert AsnCache(path).load() == {}
    path2 = tmp_path / "missing.json"
    assert AsnCache(path2).load() == {}


def test_asn_cache_undated_entries_dropped(tmp_path: Path):
    entries = {"8.8.8.8": {"asn": 15169}}  # no looked_up_at
    pruned = AsnCache.prune(entries, ttl_hours=1000, max_entries=10, now=NOW)
    assert pruned == {}


# ---------------------------------------------------------------------------
# resolve_asn_map: cache-first, cymru primary, RIPEstat fallback
# ---------------------------------------------------------------------------


def _cymru_query_factory(results: dict, calls: list):
    def _query(ips):
        calls.append(list(ips))
        return {ip: results[ip] for ip in ips if ip in results}

    return _query


def test_resolve_uses_cache_without_queries(tmp_path: Path):
    cache = AsnCache(tmp_path / "asn_cache.json")
    cache.save({
        "8.8.8.8": {"asn": 15169, "as_name": "GOOGLE", "prefix": "8.8.8.0/24",
                    "source": "cymru_whois", "looked_up_at": NOW.isoformat()},
    })
    calls: list = []
    mapping, complete = resolve_asn_map(
        ["8.8.8.8"], ASN_CFG, cache, now=NOW, whois_query=_cymru_query_factory({}, calls)
    )
    assert calls == []  # cached: no lookup at all
    assert mapping["8.8.8.8"].asn == 15169
    assert mapping["8.8.8.8"].source == "cache"
    assert complete


def test_resolve_cymru_primary(tmp_path: Path):
    cache = AsnCache(tmp_path / "asn_cache.json")
    results = {
        "8.8.8.8": AsnInfo(asn=15169, as_name="GOOGLE, US", prefix="8.8.8.0/24",
                           source="cymru_whois", looked_up_at=NOW.isoformat()),
        "9.9.9.9": AsnInfo(asn=19281, as_name="QUAD9, US", prefix="9.9.9.0/24",
                           source="cymru_whois", looked_up_at=NOW.isoformat()),
    }
    calls: list = []
    mapping, complete = resolve_asn_map(
        ["8.8.8.8", "9.9.9.9"], ASN_CFG, cache, now=NOW,
        whois_query=_cymru_query_factory(results, calls),
    )
    assert calls and calls[0] == ["8.8.8.8", "9.9.9.9"]  # one bulk batch
    assert complete
    assert mapping["9.9.9.9"].asn == 19281


def test_resolve_ripestat_fallback(tmp_path: Path, monkeypatch):
    cache = AsnCache(tmp_path / "asn_cache.json")
    calls: list = []

    def _fallback_ripestat(ip, *, url, timeout, session=None):
        calls.append(ip)
        return AsnInfo(asn=64512, as_name="EXAMPLE-HOSTING", prefix=None,
                       source="ripestat", looked_up_at=NOW.isoformat())

    monkeypatch.setattr(asnmap, "ripestat_lookup", _fallback_ripestat)
    mapping, complete = resolve_asn_map(
        ["9.9.9.9"], ASN_CFG, cache, now=NOW,
        whois_query=lambda ips: {},  # cymru answered nothing
    )
    assert calls == ["9.9.9.9"]
    assert mapping["9.9.9.9"].asn == 64512
    assert mapping["9.9.9.9"].source == "ripestat"
    assert complete


def test_resolve_incomplete_when_all_sources_fail(tmp_path: Path, monkeypatch):
    cache = AsnCache(tmp_path / "asn_cache.json")

    def _fail(ip, *, url, timeout, session=None):
        return AsnInfo(source="ripestat", looked_up_at=NOW.isoformat())

    monkeypatch.setattr(asnmap, "ripestat_lookup", _fail)
    mapping, complete = resolve_asn_map(
        ["9.9.9.9"], ASN_CFG, cache, now=NOW, whois_query=lambda ips: {}
    )
    assert mapping["9.9.9.9"].asn is None
    assert not complete  # unknown != safe: the gap is visible


def test_resolve_skips_private_and_invalid_ips(tmp_path: Path):
    cache = AsnCache(tmp_path / "asn_cache.json")
    calls: list = []
    mapping, complete = resolve_asn_map(
        ["127.0.0.1", "10.0.0.5", "not-an-ip", "8.8.8.8"],
        ASN_CFG, cache, now=NOW,
        whois_query=_cymru_query_factory(
            {"8.8.8.8": AsnInfo(asn=15169, source="cymru_whois")}, calls
        ),
    )
    assert calls == [["8.8.8.8"]]  # non-routable inputs never looked up
    assert complete


def test_generic_cloud_asn_is_plain_metadata(tmp_path: Path):
    """AWS/Google/OVH-style ASNs are enrichment, never a block signal."""
    cache = AsnCache(tmp_path / "asn_cache.json")
    mapping, _ = resolve_asn_map(
        ["8.8.8.8"], ASN_CFG, cache, now=NOW,
        whois_query=_cymru_query_factory(
            {"8.8.8.8": AsnInfo(asn=15169, as_name="GOOGLE, US", source="cymru_whois")},
            [],
        ),
    )
    info = mapping["8.8.8.8"]
    assert info.asn == 15169
    # nothing in the ASN mapping carries a decision - policy decides
    assert not hasattr(info, "status") and not hasattr(info, "blocked")
