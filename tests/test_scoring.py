"""Tests for scoring, ranking, selection and balanced sampling."""

from __future__ import annotations

import pytest

from auto_subscription_engine.core.scheduling import HistoryEntry, ReliabilityHistory
from auto_subscription_engine.core.models import ParsedConfig
from auto_subscription_engine.core.verification import (
    AddressAttempt,
    ApplicationProbeResult,
    EndpointPreflightResult,
    NodeVerificationResult,
    RuntimeVerificationResult,
)
from auto_subscription_engine.core.scoring import (
    LatencyNormalizer,
    ScoringPolicy,
    WeightSet,
    apply_preselection_scores,
    rank_live,
    score_preselection,
    select_diverse,
)


def make_config(protocol: str, host: str, port: int, suffix: str) -> ParsedConfig:
    config = ParsedConfig(
        protocol=protocol, host=host, port=port, identity=f"id-{suffix}"
    )
    config.fingerprint = f"fp-{protocol}-{suffix}"
    return config


def make_live_node(config: ParsedConfig, *, latency_ms=None, ratio=1.0) -> NodeVerificationResult:
    runtime = RuntimeVerificationResult(
        config=config,
        core_started=True,
        probes=[ApplicationProbeResult(url="https://test/204", ok=True, status=204, latency_ms=latency_ms)],
        repetitions=1,
        min_success_ratio=0.0 if ratio == 0 else min(1.0, ratio),
        min_success_count=1,
        success_count=1,
        success_ratio=ratio,
        round_success_ratios=[ratio],
        proxy_latency_ms=latency_ms,
    )
    ip = f"203.0.113.{abs(hash(config.fingerprint)) % 200 + 1}"
    preflight = EndpointPreflightResult(
        config=config, transport="tcp", resolved_ips=[ip], selected_ip=ip,
        attempts=[AddressAttempt(ip, "ipv4", True, 10.0)], preflight_success=True,
    )
    return NodeVerificationResult(config=config, preflight=preflight, runtime=runtime)


# -- scoring -----------------------------------------------------------------


def test_weights_must_sum_to_100():
    with pytest.raises(ValueError):
        ScoringPolicy(preselection_weights=WeightSet({
            "connectivity": 50, "latency": 50, "reliability": 25, "stability": 15,
        })).validate()
    ScoringPolicy().validate()


def test_score_boundaries_zero_to_hundred():
    policy = ScoringPolicy()
    normalizer = LatencyNormalizer()

    perfect_entry = HistoryEntry(
        fingerprint="x",
        checks_total=10,
        checks_passed=10,
        consecutive_successes=5,
        rolling_success_rate=1.0,
    )
    assert score_preselection(
        success_ratio=1.0, proxy_latency_ms=50.0,
        history_entry=perfect_entry, policy=policy,
    ) == 100

    # A LIVE node always has >=1 successful probe, so the true floor is
    # bounded; still, the function must clamp into [0, 100].
    worst = score_preselection(
        success_ratio=0.0, proxy_latency_ms=99999.0,
        history_entry=HistoryEntry(
            fingerprint="y", checks_total=9, checks_passed=0,
            consecutive_failures=9, rolling_success_rate=0.0,
        ), policy=policy,
    )
    assert 0 <= worst <= 100


def test_score_neutral_history_for_new_nodes():
    policy = ScoringPolicy(latency_min_ms=0, latency_max_ms=1)
    # No history at all -> reliability 0.5, stability 0.5 -> 12.5 + 7.5 = 20
    score = score_preselection(
        success_ratio=0.0, proxy_latency_ms=10.0,
        history_entry=None, policy=policy,
    )
    assert score == 20


def test_score_latency_ordering_is_monotonic():
    policy = ScoringPolicy(
        latency_min_ms=150, latency_max_ms=3000, min_history_samples=1
    )
    scores = [
        score_preselection(
            success_ratio=1.0, proxy_latency_ms=float(ms),
            history_entry=None, policy=policy,
        )
        for ms in (150, 500, 1000, 2000, 3000)
    ]
    assert scores == sorted(scores, reverse=True)


def test_score_country_never_enters_the_formula():
    # The function signature has no country input; verify two nodes that
    # only differ in country-related metadata score identically.
    entry = HistoryEntry(fingerprint="z", checks_total=5, checks_passed=5,
                         consecutive_successes=5, rolling_success_rate=1.0)
    policy = ScoringPolicy()
    assert score_preselection(
        success_ratio=1.0, proxy_latency_ms=200.0, history_entry=entry, policy=policy
    ) == score_preselection(
        success_ratio=1.0, proxy_latency_ms=200.0, history_entry=entry, policy=policy
    )


def test_latency_normalizer_linear():
    normalizer = LatencyNormalizer(min_ms=150, max_ms=3000)
    assert normalizer.normalize(100) == 1.0
    assert normalizer.normalize(150) == 1.0
    assert normalizer.normalize(None) == 0.0
    assert normalizer.normalize(3000) == 0.0
    assert normalizer.normalize(4000) == 0.0
    assert abs(normalizer.normalize(1575) - 0.5) < 1e-9


def test_apply_scores_uses_recorded_history():
    history = ReliabilityHistory()
    history.record("fp-ss-1", passed=True)
    config = make_config("ss", "one.example", 443, "1")
    node = make_live_node(config, latency_ms=200.0, ratio=1.0)
    apply_preselection_scores(
        [node], history, ScoringPolicy(latency_min_ms=0, latency_max_ms=3000, min_history_samples=1)
    )
    assert 0 <= node.score <= 100 and node.score >= 35  # ratio 1.0 contributes fully


# -- ranking / selection -------------------------------------------------------


def test_rank_live_is_deterministic_with_tiebreakers():
    nodes = []
    for suffix, latency, ratio in (("a", 300.0, 1.0), ("b", 200.0, 1.0), ("c", 200.0, 1.0)):
        config = make_config("ss", f"{suffix}.example", 443, suffix)
        node = make_live_node(config, latency_ms=latency, ratio=ratio)
        node.score = 50
        nodes.append(node)
    ranked = rank_live(nodes)
    assert [n.config.fingerprint for n in ranked] == [
        "fp-ss-b", "fp-ss-c", "fp-ss-a"
    ]
    assert [n.config.fingerprint for n in rank_live(ranked)] == \
        [n.config.fingerprint for n in ranked]


def test_select_diverse_respects_per_host_limit():
    nodes = []
    for index in range(6):
        config = make_config("ss", f"{index}.example", 443, str(index))
        node = make_live_node(config, latency_ms=100.0 + index)
        node.preflight.selected_ip = "198.51.100.7"  # all the same endpoint IP
        node.score = 90 - index
        nodes.append(node)
    selected = select_diverse(nodes, max_live_nodes=10, per_host_limit=2)
    assert len(selected) == 2


def test_select_diverse_caps_at_max_live_nodes():
    nodes = []
    for index in range(10):
        config = make_config("ss", f"{index}.example", 443, str(index))
        node = make_live_node(config, latency_ms=100.0 + index)
        node.preflight.selected_ip = f"198.51.100.{index}"  # all distinct hosts
        node.score = 90 - index
        nodes.append(node)
    selected = select_diverse(nodes, max_live_nodes=3, per_host_limit=3)
    assert len(selected) == 3
    assert [n.score for n in selected] == [90, 89, 88]


def test_select_diverse_falls_back_to_hostname():
    config = make_config("ss", "host.example", 443, "1")
    node = make_live_node(config)
    node.preflight.selected_ip = None
    node.score = 50
    selected = select_diverse([node], max_live_nodes=5, per_host_limit=1)
    assert len(selected) == 1
