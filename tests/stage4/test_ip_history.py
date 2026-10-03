from datetime import datetime, timedelta, timezone

from auto_subscription_engine.core.network import DnsHistoryStore


def test_history_records_only_public_addresses_and_recovers_recent(tmp_path):
    path = tmp_path / "ip_history.json"
    now = datetime(2026, 10, 2, 12, tzinfo=timezone.utc)
    store = DnsHistoryStore(path)
    store.observe(
        "Edge.Example.COM.",
        {
            "system": ["8.8.8.8", "10.0.0.1"],
            "doh": ["2001:4860:4860::8888"],
        },
        now=now,
    )
    store.save()

    reloaded = DnsHistoryStore.load(path)
    assert set(reloaded.recent_addresses(
        "edge.example.com",
        max_age_days=7,
        limit=10,
        now=now + timedelta(days=1),
    )) == {"8.8.8.8", "2001:4860:4860::8888"}
    assert "10.0.0.1" not in path.read_text()


def test_history_prunes_old_and_bounds_per_host(tmp_path):
    path = tmp_path / "ip_history.json"
    now = datetime(2026, 10, 2, 12, tzinfo=timezone.utc)
    store = DnsHistoryStore(path)
    for day, address in enumerate(("8.8.8.8", "8.8.4.4", "1.1.1.1")):
        store.observe(
            "edge.example.com",
            {"resolver": [address]},
            now=now - timedelta(days=day),
        )
    store.observe(
        "old.example.com",
        {"resolver": ["9.9.9.9"]},
        now=now - timedelta(days=40),
    )
    store.prune(
        retention_days=30,
        max_hosts=10,
        max_ips_per_host=2,
        now=now,
    )
    assert len(store.hosts["edge.example.com"].addresses) == 2
    assert "old.example.com" not in store.hosts
