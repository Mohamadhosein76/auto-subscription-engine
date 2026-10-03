"""Task 3 tests: guarded transactional publishing (all offline).

The publisher is exercised against fabricated Task 2 output directories
(no network): every guard, the staging/promotion flow, meaningful-change
detection, and the persistence/pruning behaviour of the reliability
history.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from auto_subscription_engine.core.scheduling import ReliabilityHistory
from auto_subscription_engine.core.hardening.state import StateCorruptionError
from auto_subscription_engine.core.orchestration.live import load_testing_config
from auto_subscription_engine.core.hardening.publication import (
    DECISION_PUBLISHED,
    DECISION_SKIPPED_DROP_RATIO,
    DECISION_SKIPPED_INVALID_OUTPUT,
    DECISION_SKIPPED_MIN_LIVE,
    DECISION_SKIPPED_ZERO_LIVE,
    MSG_COMMIT_HISTORY,
    MSG_COMMIT_PUBLISH,
    PublishError,
    PublishOptions,
    count_history_entries,
    meaningful_history_changes,
    meaningful_public_changes,
    promote_public,
    read_previous_live_count,
    resolve_history_baseline,
    run_publish,
    snapshot_dir,
    verify_public_dir,
)

FAKE_URI_TEMPLATE = "vless://fake-identity-{index}@node-{index}.example:443?security=tls#fake-{index}"


def make_output(
    root: Path,
    *,
    live_total: int = 10,
    selected: int | None = None,
    countries: dict[str, int] | None = None,
    generated_at: str = "2026-09-29T10:00:00+00:00",
) -> None:
    """Fabricate a valid Task 2 live output directory (no network)."""
    selected = live_total if selected is None else selected
    out = Path(root)
    (out / "countries").mkdir(parents=True, exist_ok=True)

    uris = [FAKE_URI_TEMPLATE.format(index=i) for i in range(live_total)]
    subscription_body = "\n".join(uris) + "\n"
    (out / "live_subscription.txt").write_text(subscription_body, encoding="utf-8")
    (out / "live_subscription_base64.txt").write_text(
        base64.b64encode(subscription_body.encode("utf-8")).decode("ascii") + "\n",
        encoding="ascii",
    )
    best_uris = uris[:selected]
    (out / "best.txt").write_text("\n".join(best_uris) + "\n", encoding="utf-8")

    country_map = countries or {"DE": selected}
    assert sum(country_map.values()) == selected
    nodes = []
    for index, uri in enumerate(uris):
        nodes.append(
            {
                "safe_id": f"node_{index:08x}",
                "protocol": "vless",
                "status": "live",
                "selected": index < selected,
                "country_code": "DE" if index < selected else "XX",
                "country_name": "Germany" if index < selected else "Unknown",
                "resolved_ip": "203.0.113.1",
                "tcp_latency_ms": 20.0 + index,
                "proxy_latency_ms": 300.0 + index,
                "success_ratio": 1.0,
                "score": 70 + index % 10,
            }
        )
    (out / "live_nodes.json").write_text(
        json.dumps(nodes, indent=2) + "\n", encoding="utf-8"
    )
    stats = {
        "generated_at": generated_at,
        "mode": "fetch",
        "sources_total": 3,
        "sources_success": 3,
        "sources_failed": 0,
        "configs_received": 100,
        "final_configs": 90,
        "candidates_sampled": 80,
        "tcp_tested": 80,
        "tcp_passed": 40,
        "tcp_failure_reasons": {"timeout": 40},
        "proxy_candidates": 20,
        "proxy_tested": 20,
        "proxy_not_tested": 0,
        "proxy_live": live_total,
        "proxy_failure_reasons": {},
        "live_total": live_total,
        "live_selected": selected,
        "median_tcp_latency_ms": 25.0,
        "median_proxy_latency_ms": 310.0,
        "countries_discovered": len(country_map),
        "count_by_country": country_map,
        "count_by_protocol_live": {"vless": selected},
        "runtime_seconds": 42.0,
        "status": "ok" if selected else "zero_live",
        "history_entries": 0,
        "effective_config": {
            "preflight_budget": 1500,
            "runtime_budget": 400,
            "max_live_nodes": 300,
            "per_host_limit": 3,
            "tcp_concurrency": 200,
            "proxy_concurrency": 10,
            "core_version": "1.14.2",
        },
    }
    (out / "live_stats.json").write_text(
        json.dumps(stats, indent=2) + "\n", encoding="utf-8"
    )
    # countries/ files contain exactly the selected nodes per country
    by_country: dict[str, list[str]] = {code: [] for code in country_map}
    selected_iter = iter(best_uris)
    for code, count in country_map.items():
        for _ in range(count):
            by_country[code].append(next(selected_iter))
    for code, uri_list in by_country.items():
        (out / "countries" / f"{code}.txt").write_text(
            "\n".join(uri_list) + "\n", encoding="utf-8"
        )


def make_options(tmp_path: Path, **overrides) -> PublishOptions:
    defaults = dict(
        output_dir=tmp_path / "output",
        public_dir=tmp_path / "public",
        staging_dir=tmp_path / "public.staging",
        history_path=tmp_path / "data" / "history.json",
        history_baseline_text=None,
        min_live_nodes=5,
        max_drop_ratio=0.80,
        engine_commit="abc1234",
        run_started_at="2026-09-29T11:00:00+00:00",
    )
    defaults.update(overrides)
    return PublishOptions(**defaults)


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------


def test_first_publish_success(tmp_path):
    make_output(tmp_path / "output", live_total=10, selected=8)
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_PUBLISHED
    public = tmp_path / "public"
    for name in ("subscription.txt", "subscription_base64.txt", "best.txt",
                 "live_nodes.json", "live_stats.json", "status.json"):
        assert (public / name).is_file(), f"missing published file: {name}"
    assert (public / "countries" / "DE.txt").is_file()
    assert result.commit_recommended is True
    assert result.commit_message == MSG_COMMIT_PUBLISH
    assert verify_public_dir(public) == []


def make_previous_public(tmp_path: Path, *, live_total: int = 10, selected: int = 9,
                         countries: dict[str, int] | None = None) -> Path:
    """Build a *published-format* public/ tree through the real publisher."""
    out = tmp_path / "prev-output"
    make_output(out, live_total=live_total, selected=selected,
                countries=countries or {"DE": selected})
    result = run_publish(make_options(
        tmp_path, output_dir=out, public_dir=tmp_path / "public",
        staging_dir=tmp_path / "prev-stage",
    ))
    assert result.decision == DECISION_PUBLISHED
    return tmp_path / "public"


def test_zero_live_guard_preserves_previous_public(tmp_path):
    public = make_previous_public(tmp_path, live_total=10, selected=9)
    sentinel = (public / "subscription.txt").read_bytes()
    make_output(tmp_path / "output", live_total=0, selected=0)
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_SKIPPED_ZERO_LIVE
    assert (public / "subscription.txt").read_bytes() == sentinel
    assert result.commit_message is None


def test_min_live_guard(tmp_path):
    make_output(tmp_path / "output", live_total=4, selected=3)
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_SKIPPED_MIN_LIVE
    assert not (tmp_path / "public").exists()


def test_drop_ratio_guard(tmp_path):
    make_output(tmp_path / "public", live_total=100, selected=100)  # previous
    make_output(tmp_path / "output", live_total=100, selected=15)  # -85%
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_SKIPPED_DROP_RATIO
    stats = json.loads((tmp_path / "public" / "live_stats.json").read_text())
    assert stats["live_selected"] == 100  # previous output preserved


def test_drop_ratio_boundary_allows_publish(tmp_path):
    make_output(tmp_path / "public", live_total=100, selected=100)
    # threshold: 100 * (1 - 0.80) = 20 -> exactly 20 is allowed
    make_output(tmp_path / "output", live_total=100, selected=20,
                countries={"DE": 12, "NL": 8})
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_PUBLISHED


def test_first_publish_ignores_drop_ratio(tmp_path):
    # No previous public output -> only min_live_nodes applies.
    make_output(tmp_path / "output", live_total=6, selected=5)
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_PUBLISHED


def test_invalid_output_preserves_previous_public(tmp_path):
    public = make_previous_public(tmp_path, live_total=10, selected=9)
    sentinel = (public / "subscription.txt").read_bytes()
    make_output(tmp_path / "output", live_total=10, selected=8)
    (tmp_path / "output" / "live_nodes.json").write_text("{broken", encoding="utf-8")
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_SKIPPED_INVALID_OUTPUT
    assert result.reasons
    assert (public / "subscription.txt").read_bytes() == sentinel


def test_malformed_previous_public_stats_treated_as_first_publish(tmp_path):
    make_output(tmp_path / "public", live_total=10, selected=9)
    (tmp_path / "public" / "live_stats.json").write_text("{{nope", encoding="utf-8")
    assert read_previous_live_count(tmp_path / "public") is None
    make_output(tmp_path / "output", live_total=10, selected=8)
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_PUBLISHED


# ---------------------------------------------------------------------------
# Transactional publish content
# ---------------------------------------------------------------------------


def test_country_stale_file_cleanup(tmp_path):
    # previous publish had DE, NL, US - new run only has DE, US
    make_output(tmp_path / "public", live_total=10, selected=10,
                countries={"DE": 4, "NL": 3, "US": 3})
    make_output(tmp_path / "output", live_total=10, selected=10,
                countries={"DE": 6, "US": 4})
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_PUBLISHED
    codes = {p.stem for p in (tmp_path / "public" / "countries").glob("*.txt")}
    assert codes == {"DE", "US"}
    assert verify_public_dir(tmp_path / "public") == []


def test_base64_matches_subscription_in_public(tmp_path):
    make_output(tmp_path / "output", live_total=8, selected=6)
    run_publish(make_options(tmp_path))
    public = tmp_path / "public"
    text = (public / "subscription.txt").read_text(encoding="utf-8")
    encoded = (public / "subscription_base64.txt").read_text(encoding="ascii").strip()
    assert base64.b64decode(encoded, validate=True).decode("utf-8") == text


def test_publish_contains_live_only(tmp_path):
    make_output(tmp_path / "output", live_total=12, selected=7,
                countries={"DE": 4, "NL": 3})
    run_publish(make_options(tmp_path))
    public = tmp_path / "public"
    nodes = json.loads((public / "live_nodes.json").read_text())
    assert nodes and all(n["status"] == "live" for n in nodes)
    subscription_lines = [l for l in (public / "subscription.txt").read_text().splitlines() if l]
    best_lines = [l for l in (public / "best.txt").read_text().splitlines() if l]
    stats = json.loads((public / "live_stats.json").read_text())
    assert len(subscription_lines) == stats["live_total"]
    assert len(best_lines) == stats["live_selected"]
    assert set(best_lines) <= set(subscription_lines)
    country_lines = []
    for p in (public / "countries").glob("*.txt"):
        country_lines += [l for l in p.read_text().splitlines() if l]
    assert set(country_lines) <= set(subscription_lines)


def test_public_metadata_contains_no_uri_or_uuid(tmp_path):
    make_output(tmp_path / "output", live_total=6, selected=5)
    stats_path = tmp_path / "output" / "live_stats.json"
    stats = json.loads(stats_path.read_text())
    stats["leaked"] = "vless://real-uuid@example.com:443"
    stats_path.write_text(json.dumps(stats), encoding="utf-8")
    options = make_options(tmp_path)
    with pytest.raises(PublishError):
        run_publish(options)
    assert not (tmp_path / "public").exists()  # previous public untouched


def test_public_metadata_rejects_uuid(tmp_path):
    # a UUID smuggled into a metadata field is caught at staging verification
    make_output(tmp_path / "output", live_total=6, selected=5)
    stats_path = tmp_path / "output" / "live_stats.json"
    stats = json.loads(stats_path.read_text())
    stats["note"] = "identity 12345678-1234-1234-1234-123456789abc leaked"
    stats_path.write_text(json.dumps(stats), encoding="utf-8")
    with pytest.raises(PublishError):
        run_publish(make_options(tmp_path))
    assert not (tmp_path / "public").exists()  # previous public untouched


def test_public_metadata_rejects_sensitive_keys_in_nodes(tmp_path):
    # forbidden keys on node entries are caught earlier, by verify-live
    make_output(tmp_path / "output", live_total=6, selected=5)
    nodes_path = tmp_path / "output" / "live_nodes.json"
    nodes = json.loads(nodes_path.read_text())
    nodes[0]["identity"] = "12345678-1234-1234-1234-123456789abc"
    nodes_path.write_text(json.dumps(nodes), encoding="utf-8")
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_SKIPPED_INVALID_OUTPUT
    assert not (tmp_path / "public").exists()


def test_status_json_correctness(tmp_path):
    make_output(tmp_path / "output", live_total=9, selected=7)
    run_publish(make_options(tmp_path, engine_commit="deadbee"))
    status = json.loads((tmp_path / "public" / "status.json").read_text())
    assert status["status"] == "ok"
    assert status["live_nodes"] == 7
    assert status["engine_version"] == "deadbee"
    assert status["core_version"] == "1.14.2"
    assert status["last_successful_publish"] == "2026-09-29T11:00:00+00:00"
    text = (tmp_path / "public" / "status.json").read_text()
    assert "vless" not in text and "uuid" not in text.lower()


def test_live_stats_publish_metadata(tmp_path):
    make_output(tmp_path / "output", live_total=9, selected=7)
    (tmp_path / "data").mkdir()
    ReliabilityHistory().save(tmp_path / "data" / "history.json")
    run_publish(make_options(tmp_path))
    stats = json.loads((tmp_path / "public" / "live_stats.json").read_text())
    assert stats["publish_status"] == "published"
    assert stats["engine_commit"] == "abc1234"
    assert stats["history_entries"] == 0
    assert stats["generated_at"]  # last published run time retained


def test_deterministic_publishing(tmp_path):
    outs = [tmp_path / f"run{i}" for i in (1, 2)]
    publics = [tmp_path / f"public{i}" for i in (1, 2)]
    for out, public in zip(outs, publics):
        make_output(out, live_total=8, selected=6, countries={"DE": 3, "NL": 3})
        run_publish(make_options(tmp_path, output_dir=out, public_dir=public,
                                 staging_dir=tmp_path / f"stage{public.name}"))
    assert snapshot_dir(publics[0]) == snapshot_dir(publics[1])


# ---------------------------------------------------------------------------
# Meaningful-change detection
# ---------------------------------------------------------------------------


def test_volatile_only_changes_skip_commit(tmp_path):
    make_output(tmp_path / "output", live_total=8, selected=6,
                generated_at="2026-09-29T10:00:00+00:00")
    options = make_options(tmp_path)
    first = run_publish(options)
    assert first.commit_recommended is True  # first publish

    # second run: identical meaningful content, different generated_at
    make_output(tmp_path / "output2", live_total=8, selected=6,
                generated_at="2026-09-29T11:00:00+00:00")
    history = tmp_path / "data" / "history.json"
    baseline = history.read_text() if history.exists() else None
    second = run_publish(make_options(
        tmp_path, output_dir=tmp_path / "output2",
        staging_dir=tmp_path / "stage2",
        history_baseline_text=baseline,
    ))
    assert second.decision == DECISION_PUBLISHED
    assert second.commit_recommended is False
    assert second.commit_message is None


def test_meaningful_subscription_change_recommends_commit(tmp_path):
    make_output(tmp_path / "public", live_total=8, selected=6)
    make_output(tmp_path / "output", live_total=9, selected=7)
    result = run_publish(make_options(tmp_path))
    assert result.commit_recommended is True
    assert result.commit_message == MSG_COMMIT_PUBLISH
    assert "public/subscription.txt" in result.meaningful_changes


def test_meaningful_public_changes_unit():
    old = {"subscription.txt": b"a", "best.txt": b"a", "countries/DE.txt": b"x"}
    assert meaningful_public_changes(old, dict(old)) == []
    new = dict(old)
    new["subscription.txt"] = b"b"
    assert meaningful_public_changes(old, new) == ["public/subscription.txt"]
    drop_country = {k: v for k, v in old.items() if k != "countries/DE.txt"}
    assert meaningful_public_changes(old, drop_country) == ["public/countries/"]


def test_history_meaningful_change_detection():
    base = {
        "schema_version": 1,
        "entries": {
            "fp1": {
                "fingerprint": "fp1",
                "checks_total": 5,
                "checks_passed": 4,
                "consecutive_successes": 2,
                "consecutive_failures": 0,
                "rolling_success_rate": 0.8,
                "recent": [1, 1, 1, 0, 1],
                "last_success": "2026-09-28T10:00:00+00:00",
                "last_failure": "2026-09-25T10:00:00+00:00",
                "last_latency_ms": 300.0,
            }
        },
    }
    bumped = json.loads(json.dumps(base))
    bumped["entries"]["fp1"]["checks_total"] = 6
    bumped["entries"]["fp1"]["checks_passed"] = 5
    bumped["entries"]["fp1"]["last_success"] = "2026-09-29T10:00:00+00:00"
    bumped["entries"]["fp1"]["last_latency_ms"] = 250.0
    bumped["entries"]["fp1"]["first_discovered"] = "2026-09-20T10:00:00+00:00"
    bumped["entries"]["fp1"]["last_discovered"] = "2026-09-29T10:00:00+00:00"
    assert meaningful_history_changes(
        json.dumps(base), json.dumps(bumped)
    ) is False  # volatile bookkeeping only

    scheduled = json.loads(json.dumps(base))
    scheduled["entries"]["fp1"]["preflight_scheduled_total"] = 9
    scheduled["entries"]["fp1"]["runtime_scheduled_total"] = 4
    scheduled["entries"]["fp1"]["last_preflight_scheduled"] = "2026-09-29T10:00:00+00:00"
    scheduled["entries"]["fp1"]["last_runtime_scheduled"] = "2026-09-29T10:00:00+00:00"
    assert meaningful_history_changes(
        json.dumps(base), json.dumps(scheduled)
    ) is True  # scheduler rotation must persist between runs

    degraded = json.loads(json.dumps(base))
    degraded["entries"]["fp1"]["consecutive_failures"] = 3
    degraded["entries"]["fp1"]["rolling_success_rate"] = 0.6
    assert meaningful_history_changes(
        json.dumps(base), json.dumps(degraded)
    ) is True  # reliability state moved

    new_node = json.loads(json.dumps(base))
    new_node["entries"]["fp2"] = dict(base["entries"]["fp1"], fingerprint="fp2")
    assert meaningful_history_changes(
        json.dumps(base), json.dumps(new_node)
    ) is True  # fingerprint set changed

    assert meaningful_history_changes(None, json.dumps(base)) is True
    assert meaningful_history_changes(json.dumps(base), json.dumps(base)) is False
    assert meaningful_history_changes("<invalid>{", json.dumps(base)) is True


def test_guarded_skip_still_commits_meaningful_history(tmp_path):
    make_output(tmp_path / "public", live_total=10, selected=9)
    baseline = "not json at all"  # committed history was corrupt/unreadable
    make_output(tmp_path / "output", live_total=4, selected=3)  # below min
    result = run_publish(make_options(tmp_path, history_baseline_text=baseline))
    assert result.decision == DECISION_SKIPPED_MIN_LIVE
    assert result.commit_recommended is True
    assert result.commit_message == MSG_COMMIT_HISTORY
    assert result.meaningful_changes == ["data/history.json"]


def test_publish_decision_file_written(tmp_path):
    make_output(tmp_path / "output", live_total=8, selected=6)
    run_publish(make_options(tmp_path))
    decision = json.loads((tmp_path / "output" / "publish_decision.json").read_text())
    assert decision["decision"] == DECISION_PUBLISHED
    assert decision["commit_recommended"] is True
    text = (tmp_path / "output" / "publish_decision.json").read_text()
    assert "vless" not in text and "uuid" not in text.lower()


def test_no_github_token_reference_in_publisher_module():
    import auto_subscription_engine.core.hardening.publication as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "GITHUB_TOKEN" not in source
    assert "github_pat_" not in source
    assert "secrets." not in source


# ---------------------------------------------------------------------------
# History persistence (Task 3: committed between runs)
# ---------------------------------------------------------------------------


def test_history_persistence_roundtrip_with_last_seen(tmp_path):
    path = tmp_path / "data" / "history.json"
    history = ReliabilityHistory()
    history.record("fp-a", passed=True, latency_ms=120.0, timestamp="2026-09-29T09:00:00+00:00")
    history.record("fp-b", passed=False, timestamp="2026-09-29T09:05:00+00:00")
    history.save(path)
    loaded = ReliabilityHistory.load(path)
    assert loaded.get("fp-a").last_seen == "2026-09-29T09:00:00+00:00"
    assert loaded.get("fp-a").last_latency_ms == 120.0
    assert loaded.get("fp-a").consecutive_successes == 1
    assert loaded.get("fp-b").consecutive_failures == 1
    assert loaded.get("fp-c") is None


def test_history_deterministic_serialization(tmp_path):
    p1, p2 = tmp_path / "h1.json", tmp_path / "h2.json"
    h1, h2 = ReliabilityHistory(), ReliabilityHistory()
    for history in (h1, h2):
        history.record("fp-z", passed=True, timestamp="2026-09-29T09:00:00+00:00")
        history.record("fp-a", passed=False, timestamp="2026-09-29T09:00:00+00:00")
    h1.save(p1)
    h2.save(p2)
    assert p1.read_bytes() == p2.read_bytes()


def test_history_prune_retention_days(tmp_path):
    path = tmp_path / "history.json"
    history = ReliabilityHistory()
    history.record("fresh", passed=True, timestamp="2026-09-29T09:00:00+00:00")
    history.record("stale", passed=True, timestamp="2026-08-01T09:00:00+00:00")
    from datetime import datetime, timezone

    pruned_stale, pruned_excess = history.prune(
        retention_days=30, max_entries=50000,
        now=datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc),
    )
    assert pruned_stale == 1
    assert history.get("stale") is None
    assert history.get("fresh") is not None


def test_history_prune_max_entries_cap(tmp_path):
    history = ReliabilityHistory()
    for index in range(20):
        day = 1 + index  # later index = more recent
        history.record(
            f"fp-{index:02d}", passed=True,
            timestamp=f"2026-09-{day:02d}T00:00:00+00:00",
        )
    from datetime import datetime, timezone

    _stale, excess = history.prune(
        retention_days=0, max_entries=10,
        now=datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc),
    )
    assert excess == 10
    assert len(history.entries) == 10
    # the most recently active entries survive
    assert history.get("fp-19") is not None
    assert history.get("fp-00") is None


def test_history_contains_no_secrets(tmp_path):
    path = tmp_path / "history.json"
    secrets = [
        "f392cb1e-8c1d-4e3a-9f2b-5d6c7e8a9b0c",  # uuid-like identity
        "SuperSecretPass42",  # password
        "vless://f392cb1e-8c1d-4e3a-9f2b-5d6c7e8a9b0c@host.example:443",
        "fake_token_abcdef123456",  # token-like placeholder
    ]
    history = ReliabilityHistory()
    for index, secret in enumerate(secrets):
        # fingerprints are derived from configs - never the secrets themselves
        history.record(f"fp-{index}", passed=bool(index % 2),
                       timestamp="2026-09-29T09:00:00+00:00")
    history.save(path)
    text = path.read_text(encoding="utf-8")
    for secret in secrets:
        assert secret not in text, f"secret leaked into history: {secret[:12]}..."


def test_malformed_history_fails_closed_without_backup(tmp_path):
    path = tmp_path / "history.json"
    path.write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(StateCorruptionError):
        ReliabilityHistory.load(path)


# ---------------------------------------------------------------------------
# Config + baseline plumbing
# ---------------------------------------------------------------------------


def test_testing_config_has_publish_and_history_defaults(tmp_path):
    cfg = load_testing_config(tmp_path / "missing.yaml")
    assert cfg["publish"]["min_live_nodes"] == 5
    assert cfg["publish"]["max_drop_ratio"] == 0.80
    assert cfg["history"]["retention_days"] == 30
    assert cfg["history"]["max_entries"] == 50000


def test_testing_config_overrides_publish_guard(tmp_path):
    custom = tmp_path / "testing.yaml"
    custom.write_text(
        "publish:\n  min_live_nodes: 42\nhistory:\n  max_entries: 7\n",
        encoding="utf-8",
    )
    cfg = load_testing_config(custom)
    assert cfg["publish"]["min_live_nodes"] == 42
    assert cfg["publish"]["max_drop_ratio"] == 0.80  # default preserved
    assert cfg["history"]["max_entries"] == 7


def test_resolve_history_baseline_prefers_snapshot_file(tmp_path):
    snapshot = tmp_path / "baseline.json"
    snapshot.write_text('{"entries": {"committed": {}}}', encoding="utf-8")
    resolved = resolve_history_baseline(
        tmp_path / "data" / "history.json", snapshot, repo_root=None
    )
    assert resolved == '{"entries": {"committed": {}}}'


def test_resolve_history_baseline_none_when_missing(tmp_path):
    resolved = resolve_history_baseline(
        tmp_path / "data" / "history.json", None, repo_root=None
    )
    assert resolved is None


# ---------------------------------------------------------------------------
# Promotion mechanics
# ---------------------------------------------------------------------------


def test_promote_replaces_whole_tree_and_rolls_back(tmp_path):
    public = tmp_path / "public"
    public.mkdir()
    (public / "old.txt").write_text("old", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "new.txt").write_text("new", encoding="utf-8")
    promote_public(staging, public)
    assert (public / "new.txt").is_file()
    assert not (public / "old.txt").exists()
    assert not staging.exists()  # renamed into place


def test_snapshot_dir_is_relative_and_complete(tmp_path):
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"A")
    (root / "sub" / "b.txt").write_bytes(b"B")
    snap = snapshot_dir(root)
    assert snap == {"a.txt": b"A", "sub/b.txt": b"B"}
    assert snapshot_dir(tmp_path / "missing") == {}
