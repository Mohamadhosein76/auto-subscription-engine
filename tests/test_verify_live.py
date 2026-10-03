"""Tests for verify-live output validation, including privacy checks."""

from __future__ import annotations

import json

from auto_subscription_engine.core.orchestration.live import verify_live_outputs
from auto_subscription_engine.core.models import ParsedConfig
from auto_subscription_engine.core.verification import (
    ApplicationProbeResult,
    EndpointPreflightResult,
    NodeVerificationResult,
    RuntimeVerificationResult,
)


def make_node(suffix: str, ip: str, country: str = "DE") -> NodeVerificationResult:
    config = ParsedConfig(
        protocol="ss",
        host=f"{suffix}.example",
        port=443,
        identity="aes-256-gcm:pw",
        original_uri=f"ss://YWVzLTI1Ni1nY206cHc@{suffix}.example:443#node",
        fingerprint=f"fp-{suffix}",
    )
    preflight = EndpointPreflightResult(
        config=config,
        transport="tcp",
        resolved_ips=[ip],
        selected_ip=ip,
        preflight_success=True,
    )
    runtime = RuntimeVerificationResult(
        config=config,
        core_started=True,
        probes=[ApplicationProbeResult(url="https://t/204", ok=True, status=204, latency_ms=150.0)],
        repetitions=1,
        min_success_ratio=1.0,
        min_success_count=1,
        success_count=1,
        success_ratio=1.0,
        round_success_ratios=[1.0],
        proxy_latency_ms=150.0,
        latency_p95_ms=150.0,
    )
    node = NodeVerificationResult(
        config=config, preflight=preflight, runtime=runtime, score=77,
        country_code=country, country_name="Germany" if country == "DE" else "Unknown",
    )
    return node


def write_outputs(tmp_path, ranked, selected, stats):
    from auto_subscription_engine.core.orchestration.live import _write_live_outputs

    selected_fps = {node.config.fingerprint for node in selected}
    _write_live_outputs(tmp_path, ranked, selected, selected_fps, stats)
    return tmp_path


def base_stats(selected_count=2):
    return {
        "configs_received": 10,
        "final_configs": 4,
        "candidates_sampled": 4,
        "tcp_tested": 4,
        "tcp_passed": 3,
        "tcp_failure_reasons": {"dns_failure": 1},
        "proxy_tested": 2,
        "proxy_live": 2,
        "proxy_not_tested": 0,
        "proxy_failure_reasons": {},
        "live_selected": selected_count,
        "status": "ok",
        "runtime_seconds": 1.0,
        "count_by_country": {"DE": selected_count},
    }


def test_valid_outputs_pass(tmp_path):
    nodes = [make_node("a", "203.0.113.1"), make_node("b", "203.0.113.2")]
    out = write_outputs(tmp_path, nodes, nodes, base_stats())
    assert verify_live_outputs(out) == []


def test_missing_file_detected(tmp_path):
    nodes = [make_node("a", "203.0.113.1")]
    out = write_outputs(tmp_path, nodes, nodes, base_stats(1))
    (out / "best.txt").unlink()
    problems = verify_live_outputs(out)
    assert any("best.txt" in p for p in problems)


def test_sensitive_key_in_live_nodes_detected(tmp_path):
    nodes = [make_node("a", "203.0.113.1")]
    out = write_outputs(tmp_path, nodes, nodes, base_stats(1))
    payload = json.loads((out / "live_nodes.json").read_text(encoding="utf-8"))
    payload[0]["original_uri"] = "ss://leak"
    (out / "live_nodes.json").write_text(json.dumps(payload), encoding="utf-8")
    problems = verify_live_outputs(out)
    assert any("leaks sensitive keys" in p for p in problems)


def test_base64_mismatch_detected(tmp_path):
    nodes = [make_node("a", "203.0.113.1")]
    out = write_outputs(tmp_path, nodes, nodes, base_stats(1))
    (out / "live_subscription_base64.txt").write_text("not-base64!!\n", encoding="ascii")
    problems = verify_live_outputs(out)
    assert any("base64" in p for p in problems)


def test_selected_count_mismatch_detected(tmp_path):
    nodes = [make_node("a", "203.0.113.1"), make_node("b", "203.0.113.2")]
    out = write_outputs(tmp_path, nodes, nodes, base_stats(2))
    stats = json.loads((out / "live_stats.json").read_text(encoding="utf-8"))
    stats["live_selected"] = 5
    (out / "live_stats.json").write_text(json.dumps(stats), encoding="utf-8")
    problems = verify_live_outputs(out)
    assert any("live_selected" in p for p in problems)


def test_countries_directory_mismatch_detected(tmp_path):
    nodes = [make_node("a", "203.0.113.1")]
    out = write_outputs(tmp_path, nodes, nodes, base_stats(1))
    (out / "countries" / "ZZ.txt").write_text("extra\n", encoding="utf-8")
    problems = verify_live_outputs(out)
    assert any("countries" in p for p in problems)


def test_missing_directory_reported(tmp_path):
    problems = verify_live_outputs(tmp_path / "does-not-exist")
    assert problems == [f"output directory not found: {tmp_path / 'does-not-exist'}"]
