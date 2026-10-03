"""Multidimensional Stage-9 score engine.

The engine consumes only credential-free evidence already produced by earlier
stages. Operator and client scores are contextual; they do not alter the global
quality score. Missing operator/client evidence is represented as ``None``
rather than silently treated as failure.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..clients.registry import CLIENTS
from ..scheduling import HistoryEntry
from .models import DimensionScore, NodeScoreCard
from .policy import ScoringPolicy
from .preselection import LatencyNormalizer


def score_node_card(
    node: dict[str, Any],
    *,
    history_entry: HistoryEntry | None,
    operator_records: dict[str, dict[str, Any] | None],
    operator_labels: dict[str, dict[str, str]] | None,
    policy: ScoringPolicy,
    now: datetime | None = None,
) -> NodeScoreCard:
    policy.validate()
    now = now or datetime.now(timezone.utc)
    connectivity = _connectivity_dimension(node)
    latency = _latency_dimension(node, policy)
    reliability = _reliability_dimension(history_entry, policy)
    freshness = _freshness_dimension(history_entry, policy, now)
    security = _security_dimension(node)
    components = {
        "connectivity": connectivity,
        "latency": latency,
        "reliability": reliability,
        "freshness": freshness,
        "security": security,
    }
    weights = policy.global_weights.values
    global_score = _weighted_score({name: dim.score for name, dim in components.items()}, weights)
    global_confidence = _weighted_score(
        {name: dim.confidence for name, dim in components.items()}, weights
    )
    operators = {
        key: _operator_dimension(record, policy, now, (operator_labels or {}).get(key, {}))
        for key, record in sorted(operator_records.items())
    }
    clients = {
        key: _client_dimension(node, key, spec.core, history_entry, policy)
        for key, spec in sorted(CLIENTS.items())
    }
    return NodeScoreCard(
        global_score=global_score,
        global_confidence=global_confidence,
        connectivity=connectivity,
        latency=latency,
        reliability=reliability,
        freshness=freshness,
        security=security,
        operators=operators,
        clients=clients,
    )


def freshness_score_for_timestamp(
    timestamp: str | None,
    *,
    policy: ScoringPolicy,
    now: datetime,
) -> tuple[int, int]:
    observed = _parse_time(timestamp)
    if observed is None:
        return 0, 0
    age_minutes = max(0.0, (now - observed).total_seconds() / 60.0)
    if age_minutes <= policy.freshness_full_minutes:
        return 100, int(round(age_minutes))
    if age_minutes >= policy.freshness_zero_minutes:
        return 0, int(round(age_minutes))
    span = policy.freshness_zero_minutes - policy.freshness_full_minutes
    value = 100.0 * (policy.freshness_zero_minutes - age_minutes) / span
    return _score(value), int(round(age_minutes))


def _connectivity_dimension(node: dict[str, Any]) -> DimensionScore:
    ratio = _unit(node.get("success_ratio", 0.0))
    evidence = int(((node.get("verification") or {}).get("success_count") or 0))
    return DimensionScore(
        score=_score(100.0 * ratio), confidence=100, status="live", evidence_count=evidence,
        details={"success_ratio": round(ratio, 4)},
    )


def _latency_dimension(node: dict[str, Any], policy: ScoringPolicy) -> DimensionScore:
    value = _float_or_none(node.get("proxy_latency_ms"))
    score = _score(100.0 * LatencyNormalizer(policy.latency_min_ms, policy.latency_max_ms).normalize(value))
    details: dict[str, Any] = {}
    if value is not None:
        details["latency_ms"] = round(value, 1)
    verification = node.get("verification") or {}
    p95 = _float_or_none(verification.get("latency_p95_ms"))
    jitter = _float_or_none(verification.get("jitter_ms"))
    if p95 is not None:
        details["p95_ms"] = round(p95, 1)
    if jitter is not None:
        details["jitter_ms"] = round(jitter, 1)
    return DimensionScore(score=score, confidence=100 if value is not None else 0, evidence_count=1 if value is not None else 0, details=details)


def _reliability_dimension(entry: HistoryEntry | None, policy: ScoringPolicy) -> DimensionScore:
    if entry is None or entry.checks_total <= 0:
        return DimensionScore(score=50, confidence=0, status="unknown", evidence_count=0)
    checks = max(0, int(entry.checks_total))
    confidence = _score(100.0 * min(1.0, checks / max(10.0, float(policy.min_history_samples))))
    if checks < policy.min_history_samples:
        return DimensionScore(
            score=50, confidence=confidence, status="warming_up", evidence_count=checks,
            details={"rolling_success_rate": round(_unit(entry.rolling_success_rate), 4)},
        )
    rolling = _unit(entry.rolling_success_rate)
    streak = min(max(0, int(entry.consecutive_successes)), 5) / 5.0
    score = _score(100.0 * (0.8 * rolling + 0.2 * streak))
    return DimensionScore(
        score=score, confidence=confidence, status="measured", evidence_count=checks,
        details={
            "rolling_success_rate": round(rolling, 4),
            "consecutive_successes": max(0, int(entry.consecutive_successes)),
        },
    )


def _freshness_dimension(entry: HistoryEntry | None, policy: ScoringPolicy, now: datetime) -> DimensionScore:
    timestamp = entry.last_success if entry is not None else None
    score, age = freshness_score_for_timestamp(timestamp, policy=policy, now=now)
    return DimensionScore(
        score=score, confidence=100 if timestamp else 0,
        status="fresh" if score > 0 else ("missing" if not timestamp else "stale"),
        fresh=bool(timestamp and age <= policy.freshness_full_minutes),
        evidence_count=1 if timestamp else 0,
        details={"age_minutes": age} if timestamp else {},
    )


def _security_dimension(node: dict[str, Any]) -> DimensionScore:
    status = str(node.get("security_status") or "missing")
    if status not in {"allow", "allow_with_warnings", "block", "quarantine"}:
        return DimensionScore(score=0, confidence=0, status="missing", evidence_count=0)
    try:
        risk = min(100, max(0, int(node.get("security_risk_score", 100))))
    except (TypeError, ValueError):
        risk = 100
    complete = bool(node.get("security_checks_complete", False))
    if status in {"block", "quarantine"}:
        value = 0
    else:
        value = 100 - risk
        if status == "allow_with_warnings":
            value = min(value, 85)
        if not complete:
            value = min(value, 60)
    return DimensionScore(
        score=_score(value), confidence=100 if complete else 60,
        status=status, evidence_count=1, details={"risk_score": risk, "checks_complete": complete},
    )


def _operator_dimension(
    record: dict[str, Any] | None,
    policy: ScoringPolicy,
    now: datetime,
    labels: dict[str, str],
) -> DimensionScore:
    label_details = {key: value for key, value in labels.items() if value}
    if not record:
        return DimensionScore(score=None, confidence=0, status="unknown", fresh=None, details=label_details)
    status = str(record.get("status") or "unknown")
    current_ratio = _unit(record.get("success_ratio", 1.0 if status == "pass" else 0.0)) if status == "pass" else 0.0
    reliability = _unit(record.get("rolling_success_rate", 0.0))
    latency_ms = _float_or_none(record.get("latency_p50_ms"))
    latency = LatencyNormalizer(policy.latency_min_ms, policy.latency_max_ms).normalize(latency_ms)
    fresh_score, age = freshness_score_for_timestamp(str(record.get("last_observed_at") or ""), policy=policy, now=now)
    values = {
        "connectivity": 100.0 * current_ratio,
        "reliability": 100.0 * reliability,
        "latency": 100.0 * latency,
        "freshness": float(fresh_score),
    }
    value = _weighted_score(values, policy.operator_weights.values)
    checks = max(0, int(record.get("checks_total", 0) or 0))
    confidence = _score(100.0 * min(1.0, checks / 5.0))
    details = dict(label_details)
    details.update({
        "rolling_success_rate": round(reliability, 4),
        "success_ratio": round(current_ratio, 4),
        "age_minutes": age,
    })
    if latency_ms is not None:
        details["latency_ms"] = round(latency_ms, 1)
    runtime_core = record.get("runtime_core")
    if runtime_core:
        details["runtime_core"] = str(runtime_core)
    return DimensionScore(
        score=value, confidence=confidence, status=status,
        fresh=bool(record.get("fresh", False)), evidence_count=checks, details=details,
    )


def _client_dimension(
    node: dict[str, Any], client: str, core: str,
    history_entry: HistoryEntry | None, policy: ScoringPolicy,
) -> DimensionScore:
    status = node.get(f"{core}_compatible")
    if status in (None, "unavailable", "untested"):
        return DimensionScore(
            score=None, confidence=0, status=str(status or "unknown"), fresh=True,
            details={"core": core},
        )
    if status in {"fail", "unsupported"}:
        return DimensionScore(
            score=0, confidence=100, status=str(status), fresh=True, evidence_count=1,
            details={"core": core},
        )
    if status != "pass":
        return DimensionScore(score=None, confidence=0, status=str(status), fresh=True, details={"core": core})
    bucket = ((history_entry.cores or {}).get(core) if history_entry is not None else None) or {}
    checks = max(0, int(bucket.get("checks", 0) or 0))
    passed = max(0, int(bucket.get("passed", 0) or 0))
    core_reliability = (passed / checks) if checks else 0.5
    latency_ms = _float_or_none((node.get("compat_latency_ms") or {}).get(core))
    latency = LatencyNormalizer(policy.latency_min_ms, policy.latency_max_ms).normalize(latency_ms)
    values = {
        "runtime": 100.0,
        "reliability": 100.0 * core_reliability,
        "latency": 100.0 * latency,
    }
    value = _weighted_score(values, policy.client_weights.values)
    confidence = _score(70.0 + 30.0 * min(1.0, checks / 5.0))
    details: dict[str, Any] = {"core": core, "core_success_rate": round(core_reliability, 4)}
    if latency_ms is not None:
        details["latency_ms"] = round(latency_ms, 1)
    return DimensionScore(score=value, confidence=confidence, status="pass", fresh=True, evidence_count=max(1, checks), details=details)


def _weighted_score(values: dict[str, int | float | None], weights: dict[str, float]) -> int:
    total = 0.0
    applied = 0.0
    for key, weight in weights.items():
        value = values.get(key)
        if value is None:
            continue
        total += float(weight) * min(100.0, max(0.0, float(value))) / 100.0
        applied += float(weight)
    if applied <= 0:
        return 0
    return _score(total * 100.0 / applied)


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _unit(value: Any) -> float:
    try:
        return min(1.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _score(value: float) -> int:
    return int(round(min(100.0, max(0.0, float(value)))))
