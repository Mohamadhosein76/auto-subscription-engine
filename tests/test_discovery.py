"""Stage 3 discovery engine tests: recursion, dedupe, scoring and quarantine."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import auto_subscription_engine.core.discovery.engine as engine_mod
from auto_subscription_engine.core.discovery import (
    DiscoveryEngine,
    DiscoveryPolicy,
    FetchOutcome,
    SourceDefinition,
    SourceIntelligenceStore,
    canonicalize_source_url,
    load_discovery_policy,
    source_id_for_url,
)


def source(name: str, url: str, *, priority: int = 50) -> SourceDefinition:
    return SourceDefinition(
        name=name,
        url=url,
        priority=priority,
        source_id=source_id_for_url(url),
    )


def test_source_url_canonicalization_removes_fragment_and_default_port() -> None:
    assert canonicalize_source_url("HTTPS://Example.COM:443/sub#x") == "https://example.com/sub"
    assert canonicalize_source_url("http://Example.COM:80") == "http://example.com/"


def test_policy_loader(tmp_path: Path) -> None:
    path = tmp_path / "discovery.yaml"
    path.write_text("discovery:\n  max_depth: 3\n  max_sources: 20\n", encoding="utf-8")
    policy = load_discovery_policy(path)
    assert policy.max_depth == 3
    assert policy.max_sources == 20
    assert policy.max_total_proxies == 50000


def test_recursive_nested_discovery_and_proxy_dedupe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = source("root", "https://root.example/sub")
    child_url = "https://child.example/provider"
    root_body = f"""
proxies:
  - name: one
    type: vless
    server: edge.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    tls: true
proxy-providers:
  child:
    type: http
    url: {child_url}
"""
    child_body = (
        "vless://11111111-2222-3333-4444-555555555555@edge.example.com:443?security=tls#dup\n"
        "trojan://secret@two.example.com:443?security=tls#two\n"
    )

    def fake_fetch(item, **kwargs):
        body = root_body if item.name == "root" else child_body
        return FetchOutcome(item, ok=True, status_code=200, content=body, byte_count=len(body))

    monkeypatch.setattr(engine_mod, "fetch_source", fake_fetch)
    state_path = tmp_path / "discovery.json"
    result = DiscoveryEngine(
        [root],
        policy=DiscoveryPolicy(max_depth=2, max_sources=8),
        state_path=state_path,
    ).discover()

    assert result.sources_success == 2
    assert result.sources_failed == 0
    assert len(result.nested_sources) == 1
    assert len(result.proxies) == 2
    assert result.duplicates_removed == 1
    assert {proxy.protocol for proxy in result.proxies} == {"vless", "trojan"}
    assert state_path.is_file()


def test_max_depth_prevents_nested_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    root = source("root", "https://root.example/sub")
    calls: list[str] = []

    def fake_fetch(item, **kwargs):
        calls.append(item.name)
        body = "https://child.example/sub\n"
        return FetchOutcome(item, ok=True, status_code=200, content=body, byte_count=len(body))

    monkeypatch.setattr(engine_mod, "fetch_source", fake_fetch)
    result = DiscoveryEngine([root], policy=DiscoveryPolicy(max_depth=0)).discover()
    assert calls == ["root"]
    assert result.sources_success == 1


def test_duplicate_nested_url_only_fetched_once(monkeypatch: pytest.MonkeyPatch) -> None:
    root = source("root", "https://root.example/sub")
    fetched: list[str] = []

    def fake_fetch(item, **kwargs):
        fetched.append(item.url)
        if item.name == "root":
            body = "https://child.example/sub\nhttps://child.example:443/sub#fragment\n"
        else:
            body = "trojan://pw@edge.example.com:443#x\n"
        return FetchOutcome(item, ok=True, status_code=200, content=body, byte_count=len(body))

    monkeypatch.setattr(engine_mod, "fetch_source", fake_fetch)
    result = DiscoveryEngine([root], policy=DiscoveryPolicy(max_depth=2)).discover()
    assert len(fetched) == 2
    assert result.sources_success == 2


def test_quarantine_after_consecutive_failures(tmp_path: Path) -> None:
    item = source("bad", "https://bad.example/sub")
    store = SourceIntelligenceStore()
    for _ in range(3):
        stats = store.record_fetch(
            item,
            ok=False,
            quarantine_after_failures=3,
            quarantine_base_minutes=30,
            quarantine_max_hours=24,
        )
    assert stats.is_quarantined()
    store.save(tmp_path / "state.json")
    loaded = SourceIntelligenceStore.load(tmp_path / "state.json")
    assert loaded.get(item.source_id) is not None
    assert loaded.get(item.source_id).is_quarantined()


def test_success_clears_quarantine() -> None:
    item = source("recover", "https://recover.example/sub")
    store = SourceIntelligenceStore()
    for _ in range(3):
        store.record_fetch(item, ok=False)
    assert store.get(item.source_id).is_quarantined()
    store.record_fetch(item, ok=True, proxies_seen=5, unique_proxies=4)
    assert not store.get(item.source_id).is_quarantined()
    assert store.get(item.source_id).consecutive_failures == 0


def test_quality_improves_with_real_verification() -> None:
    item = source("good", "https://good.example/sub")
    store = SourceIntelligenceStore()
    store.record_fetch(item, ok=True, proxies_seen=100, unique_proxies=90)
    before = store.quality(item.source_id)
    store.record_verification(
        item.source_id,
        tcp_tested=80,
        tcp_passed=70,
        proxy_tested=60,
        proxy_passed=55,
        compat_tested=50,
        compat_passed=48,
        published=40,
    )
    assert store.quality(item.source_id) > before


def test_discovery_state_never_persists_source_url_or_query_secret(tmp_path: Path) -> None:
    item = source("public-source", "https://example.com/sub?token=SUPER_SECRET_TOKEN")
    store = SourceIntelligenceStore()
    store.record_fetch(item, ok=True, proxies_seen=2, unique_proxies=2)
    path = tmp_path / "discovery.json"
    store.save(path)
    text = path.read_text(encoding="utf-8")
    assert "SUPER_SECRET_TOKEN" not in text
    assert "https://" not in text
    payload = json.loads(text)
    assert item.source_id in payload["sources"]


def test_scheduler_prefers_priority_and_quality(monkeypatch: pytest.MonkeyPatch) -> None:
    high = source("high", "https://high.example/sub", priority=90)
    low = source("low", "https://low.example/sub", priority=10)
    calls: list[str] = []

    def fake_fetch(item, **kwargs):
        calls.append(item.name)
        return FetchOutcome(item, ok=True, status_code=200, content="", byte_count=0)

    monkeypatch.setattr(engine_mod, "fetch_source", fake_fetch)
    DiscoveryEngine([low, high], policy=DiscoveryPolicy(max_sources=2)).discover()
    assert calls == ["high", "low"]


def test_source_failure_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = source("bad", "https://bad.example/sub")
    good = source("good", "https://good.example/sub")

    def fake_fetch(item, **kwargs):
        if item.name == "bad":
            raise RuntimeError("boom")
        return FetchOutcome(
            item,
            ok=True,
            status_code=200,
            content="trojan://pw@edge.example.com:443#ok\n",
            byte_count=10,
        )

    monkeypatch.setattr(engine_mod, "fetch_source", fake_fetch)
    result = DiscoveryEngine([bad, good]).discover()
    assert result.sources_failed == 1
    assert result.sources_success == 1
    assert len(result.proxies) == 1
