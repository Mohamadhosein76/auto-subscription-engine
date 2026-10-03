"""Stage 6 adaptive scheduler tests (all deterministic/offline)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from auto_subscription_engine.core.models import ParsedConfig
from auto_subscription_engine.core.scheduling import (
    CandidateLane,
    CandidateScheduler,
    ReliabilityHistory,
    SchedulerPolicy,
    policy_from_mapping,
)
from auto_subscription_engine.core.verification import AddressAttempt, EndpointPreflightResult

NOW = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)


def cfg(index: int, *, protocol: str = "vless", source: str = "source-a", host: str | None = None) -> ParsedConfig:
    item = ParsedConfig(
        protocol=protocol,
        host=host or f"node-{index}.example",
        port=443,
        identity=f"id-{index}",
        source=source,
    )
    item.fingerprint = f"fp-{index:03d}"
    return item


def policy(**overrides) -> SchedulerPolicy:
    values = dict(
        preflight_budget=10,
        runtime_budget=5,
        exploration_share=0.4,
        recovery_share=0.2,
        direct_ip_share=0.2,
        source_base_share=0.2,
        source_quality_bonus_share=0.3,
        healthy_retest_minutes=180,
        flaky_retest_minutes=45,
        exploration_retry_minutes=60,
        recovery_base_minutes=30,
        recovery_max_hours=12,
        stale_after_hours=24,
        flaky_success_rate=0.75,
        allow_early_fill=True,
    )
    values.update(overrides)
    return SchedulerPolicy(**values)


def test_never_tested_candidates_rotate_across_runs_without_starvation():
    history = ReliabilityHistory()
    configs = [cfg(i) for i in range(10)]
    first = CandidateScheduler(policy=policy(), history=history, now=NOW)
    plan1 = first.plan_preflight(configs, budget=3)
    first.mark_selected(plan1)

    second = CandidateScheduler(policy=policy(), history=history, now=NOW + timedelta(minutes=1))
    plan2 = second.plan_preflight(configs, budget=3)

    fps1 = {item.fingerprint for item in plan1.selected}
    fps2 = {item.fingerprint for item in plan2.selected}
    assert len(fps1) == len(fps2) == 3
    assert fps1.isdisjoint(fps2)
    assert all(history.get(fp).preflight_scheduled_total == 1 for fp in fps1)


def test_recovery_exponential_backoff_blocks_early_retest_then_becomes_due():
    history = ReliabilityHistory()
    item = cfg(1)
    ts = NOW.isoformat(timespec="seconds")
    history.record(item.fingerprint, passed=False, timestamp=ts)
    history.record(item.fingerprint, passed=False, timestamp=ts)
    p = policy(recovery_base_minutes=30, allow_early_fill=False)

    early = CandidateScheduler(policy=p, history=history, now=NOW + timedelta(minutes=59))
    assert early.plan_preflight([item], budget=1).selected == []

    due = CandidateScheduler(policy=p, history=history, now=NOW + timedelta(minutes=61))
    plan = due.plan_preflight([item], budget=1)
    assert [x.fingerprint for x in plan.selected] == [item.fingerprint]
    decision = plan.decisions[0]
    assert decision.lane == CandidateLane.RECOVERY and decision.due is True


def test_healthy_nodes_obey_retest_ttl():
    history = ReliabilityHistory()
    item = cfg(2)
    history.record(item.fingerprint, passed=True, timestamp=NOW.isoformat(timespec="seconds"))
    p = policy(healthy_retest_minutes=180, allow_early_fill=False)
    not_due = CandidateScheduler(policy=p, history=history, now=NOW + timedelta(minutes=179))
    assert not_due.plan_preflight([item], budget=1).selected == []
    due = CandidateScheduler(policy=p, history=history, now=NOW + timedelta(minutes=181))
    assert due.plan_preflight([item], budget=1).selected


def test_direct_ip_reserve_promotes_static_ip_variants():
    history = ReliabilityHistory()
    configs = [cfg(i) for i in range(8)] + [cfg(100, host="8.8.8.8"), cfg(101, host="1.1.1.1")]
    scheduler = CandidateScheduler(policy=policy(direct_ip_share=0.4), history=history, now=NOW)
    plan = scheduler.plan_preflight(configs, budget=5)
    assert any(item.host in {"8.8.8.8", "1.1.1.1"} for item in plan.selected)
    assert plan.summary()["direct_ip_selected"] >= 1


def test_protocol_round_robin_prevents_one_protocol_monopoly():
    history = ReliabilityHistory()
    configs = [cfg(i, protocol="vless") for i in range(20)]
    configs += [cfg(100 + i, protocol="trojan") for i in range(4)]
    scheduler = CandidateScheduler(policy=policy(), history=history, now=NOW)
    plan = scheduler.plan_preflight(configs, budget=6)
    protocols = [item.protocol for item in plan.selected]
    assert "vless" in protocols and "trojan" in protocols
    assert protocols[:2][0] != protocols[:2][1]


def test_source_quality_changes_soft_budget_without_excluding_low_quality_source():
    history = ReliabilityHistory()
    configs = [cfg(i, source="good") for i in range(20)]
    configs += [cfg(100 + i, source="weak") for i in range(20)]
    scheduler = CandidateScheduler(
        policy=policy(source_base_share=0.1, source_quality_bonus_share=0.5),
        history=history,
        source_quality={"good": 1.0, "weak": 0.0},
        now=NOW,
    )
    plan = scheduler.plan_preflight(configs, budget=10)
    counts = plan.summary()["selected_by_source"]
    assert counts["good"] > counts["weak"]
    assert counts["weak"] >= 1


def test_runtime_budget_promotes_preflight_survivor_never_runtime_scheduled():
    history = ReliabilityHistory()
    a, b = cfg(1), cfg(2)
    for item in (a, b):
        history.observe_candidate(item.fingerprint, timestamp=NOW.isoformat(timespec="seconds"))
    history.mark_scheduled(a.fingerprint, phase="runtime", timestamp=NOW.isoformat(timespec="seconds"))
    results = [
        EndpointPreflightResult(
            config=item,
            transport="tcp",
            resolved_ips=["8.8.8.8"],
            selected_ip="8.8.8.8",
            attempts=[AddressAttempt("8.8.8.8", "ipv4", True, latency)],
            preflight_success=True,
        )
        for item, latency in ((a, 10.0), (b, 100.0))
    ]
    scheduler = CandidateScheduler(policy=policy(allow_early_fill=True), history=history, now=NOW + timedelta(minutes=1))
    plan = scheduler.plan_runtime(results, budget=1)
    assert plan.selected[0].config.fingerprint == b.fingerprint


def test_policy_mapping_validates_ranges():
    mapped = policy_from_mapping({"preflight_budget": 20, "runtime_budget": 7})
    assert mapped.preflight_budget == 20 and mapped.runtime_budget == 7
    with pytest.raises(ValueError):
        policy_from_mapping({"preflight_budget": 0})
    with pytest.raises(ValueError):
        policy_from_mapping({"exploration_share": 0.9, "recovery_share": 0.3})


def test_scheduler_state_roundtrips_in_history(tmp_path):
    path = tmp_path / "history.json"
    history = ReliabilityHistory()
    item = cfg(9)
    history.observe_candidate(item.fingerprint, timestamp=NOW.isoformat(timespec="seconds"))
    history.mark_scheduled(item.fingerprint, phase="preflight", timestamp=NOW.isoformat(timespec="seconds"))
    history.mark_scheduled(item.fingerprint, phase="runtime", timestamp=NOW.isoformat(timespec="seconds"))
    history.save(path)
    loaded = ReliabilityHistory.load(path)
    entry = loaded.get(item.fingerprint)
    assert entry.first_discovered == NOW.isoformat(timespec="seconds")
    assert entry.preflight_scheduled_total == 1
    assert entry.runtime_scheduled_total == 1


def test_large_never_tested_pool_is_covered_before_recent_candidates_repeat():
    history = ReliabilityHistory()
    configs = [cfg(i, protocol=("vless" if i % 2 == 0 else "trojan")) for i in range(20)]
    seen: set[str] = set()
    for minute in range(4):
        scheduler = CandidateScheduler(
            policy=policy(exploration_retry_minutes=60),
            history=history,
            now=NOW + timedelta(minutes=minute),
        )
        plan = scheduler.plan_preflight(configs, budget=5)
        current = {item.fingerprint for item in plan.selected}
        assert len(current) == 5
        assert current.isdisjoint(seen)
        seen.update(current)
        scheduler.mark_selected(plan)
    assert len(seen) == 20
