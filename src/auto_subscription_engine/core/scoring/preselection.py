"""Pre-security verification quality used for bounded live selection.

This preserves the Stage-1..8 ranking semantics, but the implementation now
lives under the single Stage-9 scoring subsystem. Final multidimensional scores
are produced later, after security and client compatibility evidence exists.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ..scheduling import HistoryEntry, ReliabilityHistory
from ..verification import NodeVerificationResult
from .policy import ScoringPolicy


@dataclass(frozen=True)
class LatencyNormalizer:
    min_ms: float = 150.0
    max_ms: float = 3000.0

    def normalize(self, latency_ms: float | None) -> float:
        if latency_ms is None:
            return 0.0
        if latency_ms <= self.min_ms:
            return 1.0
        if latency_ms >= self.max_ms:
            return 0.0
        return (self.max_ms - latency_ms) / (self.max_ms - self.min_ms)


def latency_score(latency_ms: float | None, normalizer: LatencyNormalizer) -> float:
    return normalizer.normalize(latency_ms)


def score_preselection(
    *,
    success_ratio: float,
    proxy_latency_ms: float | None,
    history_entry: HistoryEntry | None,
    policy: ScoringPolicy,
) -> int:
    policy.validate()
    weights = policy.preselection_weights.values
    conn = _unit(success_ratio)
    if history_entry is not None and history_entry.checks_total >= policy.min_history_samples:
        reliability = _unit(history_entry.rolling_success_rate)
    else:
        reliability = 0.5
    if history_entry is not None and history_entry.checks_total >= 1:
        stability = min(history_entry.consecutive_successes, 5) / 5.0
    else:
        stability = 0.5
    latency = LatencyNormalizer(policy.latency_min_ms, policy.latency_max_ms).normalize(proxy_latency_ms)
    total = (
        weights["connectivity"] * conn
        + weights["latency"] * latency
        + weights["reliability"] * reliability
        + weights["stability"] * stability
    )
    return _score(total)


def apply_preselection_scores(
    results: list[NodeVerificationResult],
    history: ReliabilityHistory,
    policy: ScoringPolicy,
) -> None:
    for result in results:
        if result.status != "live":
            continue
        result.score = score_preselection(
            success_ratio=result.proxy.success_ratio if result.proxy is not None else 0.0,
            proxy_latency_ms=result.proxy.proxy_latency_ms if result.proxy is not None else None,
            history_entry=history.get(result.config.fingerprint),
            policy=policy,
        )


def rank_live(results: Iterable[NodeVerificationResult]) -> list[NodeVerificationResult]:
    def sort_key(result: NodeVerificationResult) -> tuple[int, float, str]:
        latency = (
            result.proxy.proxy_latency_ms
            if result.proxy is not None and result.proxy.proxy_latency_ms is not None
            else float("inf")
        )
        return (-result.score, latency, result.config.fingerprint)
    return sorted(results, key=sort_key)


def select_diverse(
    ranked: Sequence[NodeVerificationResult], *, max_live_nodes: int, per_host_limit: int
) -> list[NodeVerificationResult]:
    if max_live_nodes <= 0 or per_host_limit <= 0:
        return []
    per_host: dict[str, int] = {}
    selected: list[NodeVerificationResult] = []
    for result in ranked:
        host_key = (
            result.tcp.resolved_ip
            if result.tcp is not None and result.tcp.resolved_ip
            else (result.config.host or "")
        )
        if per_host.get(host_key, 0) >= per_host_limit:
            continue
        per_host[host_key] = per_host.get(host_key, 0) + 1
        selected.append(result)
        if len(selected) >= max_live_nodes:
            break
    return selected


def _unit(value: float) -> float:
    return min(1.0, max(0.0, float(value)))


def _score(value: float) -> int:
    return int(round(min(100.0, max(0.0, value))))
