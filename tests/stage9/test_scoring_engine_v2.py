from __future__ import annotations

from datetime import datetime, timedelta, timezone

from auto_subscription_engine.core.scheduling import HistoryEntry
from auto_subscription_engine.core.scoring import ScoringPolicy, score_node_card


def _node(**overrides):
    node = {
        "safe_id": "node_test",
        "success_ratio": 1.0,
        "proxy_latency_ms": 150.0,
        "verification": {"success_count": 6, "latency_p95_ms": 180.0, "jitter_ms": 8.0},
        "security_status": "allow",
        "security_risk_score": 0,
        "security_checks_complete": True,
        "xray_compatible": "pass",
        "hiddify_compatible": "pass",
        "singbox_compatible": "pass",
        "mihomo_compatible": "pass",
        "compat_latency_ms": {"xray": 150.0, "hiddify": 150.0, "singbox": 150.0, "mihomo": 150.0},
    }
    node.update(overrides)
    return node


def _history(now: datetime) -> HistoryEntry:
    ts = now.isoformat(timespec="seconds")
    return HistoryEntry(
        fingerprint="fp",
        checks_total=10,
        checks_passed=10,
        consecutive_successes=5,
        rolling_success_rate=1.0,
        last_success=ts,
        last_seen=ts,
        cores={
            "xray": {"checks": 5, "passed": 5},
            "hiddify": {"checks": 5, "passed": 5},
            "singbox": {"checks": 5, "passed": 5},
            "mihomo": {"checks": 5, "passed": 5},
        },
    )


def test_perfect_evidence_produces_full_multidimensional_scores():
    now = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
    operator = {
        "status": "pass",
        "success_ratio": 1.0,
        "rolling_success_rate": 1.0,
        "latency_p50_ms": 150.0,
        "last_observed_at": now.isoformat(timespec="seconds"),
        "checks_total": 5,
        "runtime_core": "xray",
        "fresh": True,
    }
    card = score_node_card(
        _node(), history_entry=_history(now),
        operator_records={"mci": operator},
        operator_labels={"mci": {"display_name": "MCI", "network_type": "mobile"}},
        policy=ScoringPolicy(), now=now,
    )
    assert card.global_score == 100
    assert card.reliability.score == 100
    assert card.freshness.score == 100
    assert card.security.score == 100
    assert card.operators["mci"].score == 100
    assert card.clients["v2rayng"].score == 100
    assert card.clients["hiddify"].score == 100
    assert card.clients["mihomo"].score == 100


def test_unknown_operator_is_not_misrepresented_as_failure():
    now = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
    card = score_node_card(
        _node(), history_entry=_history(now), operator_records={"mci": None},
        operator_labels={}, policy=ScoringPolicy(), now=now,
    )
    assert card.operators["mci"].score is None
    assert card.operators["mci"].status == "unknown"
    assert card.operators["mci"].confidence == 0


def test_explicit_client_failure_is_zero_but_unavailable_is_unknown():
    now = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
    node = _node(xray_compatible="fail", mihomo_compatible="unavailable")
    card = score_node_card(
        node, history_entry=_history(now), operator_records={}, operator_labels={},
        policy=ScoringPolicy(), now=now,
    )
    assert card.clients["v2rayng"].score == 0
    assert card.clients["v2rayng"].status == "fail"
    assert card.clients["mihomo"].score is None
    assert card.clients["mihomo"].status == "unavailable"


def test_stale_operator_evidence_decays_without_becoming_current_truth():
    now = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
    record = {
        "status": "pass", "success_ratio": 1.0, "rolling_success_rate": 1.0,
        "latency_p50_ms": 150.0,
        "last_observed_at": (now - timedelta(days=2)).isoformat(timespec="seconds"),
        "checks_total": 8, "fresh": False,
    }
    card = score_node_card(
        _node(), history_entry=_history(now), operator_records={"mci": record},
        operator_labels={}, policy=ScoringPolicy(), now=now,
    )
    assert card.operators["mci"].fresh is False
    assert card.operators["mci"].score is not None
    assert card.operators["mci"].score < 100


def test_incomplete_security_evidence_is_capped():
    now = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
    card = score_node_card(
        _node(security_checks_complete=False), history_entry=_history(now),
        operator_records={}, operator_labels={}, policy=ScoringPolicy(), now=now,
    )
    assert card.security.score == 60
    assert card.global_score < 100
