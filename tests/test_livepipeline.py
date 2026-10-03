"""Offline integration tests for the Stage 5 live-pipeline orchestration."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import auto_subscription_engine.core.orchestration.live as lp
from auto_subscription_engine.core.models import ParsedConfig, SourceConfigError
from auto_subscription_engine.core.verification import (
    ApplicationProbeResult,
    EndpointPreflightResult,
    RuntimeVerificationResult,
)
from auto_subscription_engine.core.network.geo import GeoInfo
from auto_subscription_engine.core.scheduling import ReliabilityHistory
from auto_subscription_engine.core.orchestration.live import (
    LiveOptions,
    SystemicPipelineError,
    load_testing_config,
    run_live_pipeline,
    verify_live_outputs,
)
from auto_subscription_engine.core.orchestration.pipeline import RunOptions

TESTING_YAML = """
scheduler:
  preflight_budget: 10
  runtime_budget: 5
  exploration_share: 0.4
  recovery_share: 0.2
  direct_ip_share: 0.1
  source_base_share: 0.2
  source_quality_bonus_share: 0.2
  healthy_retest_minutes: 180
  flaky_retest_minutes: 45
  exploration_retry_minutes: 60
  recovery_base_minutes: 30
  recovery_max_hours: 12
  stale_after_hours: 24
  flaky_success_rate: 0.75
  allow_early_fill: true
selection:
  max_live_nodes: 5
  per_host_limit: 2
verification:
  connect_timeout_seconds: 1.0
  preflight_concurrency: 20
  max_addresses_per_node: 4
  runtime_concurrency: 4
  startup_timeout_seconds: 1.0
  http_timeout_seconds: 1.0
  repetitions: 1
  min_success_ratio: 1.0
  min_success_count: 1
  soft_deadline_seconds: 60.0
  targets:
    - url: "https://test/generate_204"
      expect_status: [204]
"""


def make_configs(count: int = 12) -> list[ParsedConfig]:
    configs = []
    protocols = ("vless", "vmess", "trojan", "ss", "hysteria2")
    for index in range(count):
        kind = "live" if index % 2 == 0 else "dead"
        protocol = protocols[index % len(protocols)]
        config = ParsedConfig(
            protocol=protocol,
            host=f"node-{index}.example",
            port=443 + index,
            identity=f"id-{index}",
            original_uri=f"{protocol}://id-{index}@node-{index}.example:443",
        )
        config.fingerprint = f"fp-{kind}-{index:02d}"
        configs.append(config)
    return configs


def fake_collect_configs(options: RunOptions):
    configs = make_configs()
    return configs, {
        "mode": "offline",
        "sources_total": 1,
        "sources_success": 1,
        "sources_failed": 0,
        "configs_received": 20,
        "configs_unknown_protocol": 0,
        "configs_invalid": 8,
        "configs_valid": 12,
        "duplicates_removed": 0,
        "final_configs": len(configs),
        "count_by_protocol": {"ss": 1, "vless": 1},
        "invalid_reasons": {},
        "sources": [],
    }


class FakeVerificationEngine:
    def __init__(self, core_path, policy):
        self.policy = policy

    def preflight(self, configs):
        results = []
        for config in configs:
            if "dead" in config.fingerprint:
                results.append(
                    EndpointPreflightResult(
                        config=config,
                        transport="tcp",
                        preflight_success=False,
                        failure_reason="dns_failure",
                    )
                )
            else:
                index = int(config.fingerprint[-2:])
                results.append(
                    EndpointPreflightResult(
                        config=config,
                        transport="udp" if config.protocol == "hysteria2" else "tcp",
                        resolved_ips=[f"203.0.113.{index}"],
                        selected_ip=f"203.0.113.{index}",
                        preflight_success=True,
                    )
                )
        return results

    def runtime(self, candidates):
        results = []
        for item in candidates:
            result = RuntimeVerificationResult(
                config=item.config,
                core_started=True,
                repetitions=1,
                min_success_ratio=1.0,
                min_success_count=1,
            )
            result.probes = [
                ApplicationProbeResult(
                    url="https://test/generate_204",
                    ok=True,
                    status=204,
                    latency_ms=120.0,
                )
            ]
            result.success_count = 1
            result.success_ratio = 1.0
            result.round_success_ratios = [1.0]
            result.proxy_latency_ms = 120.0
            result.latency_p95_ms = 120.0
            results.append(result)
        return results, 0


class FakeGeoResolver:
    def __init__(self, settings):
        self.settings = settings

    def lookup_many(self, ips):
        return {
            ip: (GeoInfo("UNKNOWN", "Unknown") if ip.endswith(".4") else GeoInfo("DE", "Germany"))
            for ip in ips
        }


@pytest.fixture()
def live_env(tmp_path, monkeypatch):
    testing_config = tmp_path / "testing.yaml"
    testing_config.write_text(TESTING_YAML, encoding="utf-8")
    output_dir = tmp_path / "output"
    history_path = tmp_path / "history.json"
    core_path = tmp_path / "sing-box"
    core_path.write_text("#!/bin/sh\n")
    core_path.chmod(0o755)
    monkeypatch.setattr(lp, "collect_configs", fake_collect_configs)
    monkeypatch.setattr(lp, "VerificationEngine", FakeVerificationEngine)
    monkeypatch.setattr(lp, "GeoResolver", FakeGeoResolver)
    return {
        "testing_config": testing_config,
        "output_dir": output_dir,
        "history_path": history_path,
        "core_path": core_path,
        "tmp_path": tmp_path,
    }


def make_options(env, **overrides):
    defaults = dict(
        config_path=Path("config/sources.yaml"),
        testing_config_path=env["testing_config"],
        output_dir=env["output_dir"],
        core_paths={"singbox": env["core_path"]},
        history_path=env["history_path"],
        discovery_state_path=env["tmp_path"] / "discovery.json",
    )
    defaults.update(overrides)
    return LiveOptions(**defaults)


def test_load_testing_config_merges_and_validates(tmp_path):
    path = tmp_path / "testing.yaml"
    path.write_text(TESTING_YAML, encoding="utf-8")
    config = load_testing_config(path)
    assert config["scheduler"]["preflight_budget"] == 10
    assert config["verification"]["repetitions"] == 1
    assert config["scoring"]["preselection_weights"]["connectivity"] == 35.0


def test_load_testing_config_rejects_bad_weights(tmp_path):
    path = tmp_path / "testing.yaml"
    path.write_text(
        "scoring:\n  weights:\n    connectivity: 50\n    latency: 50\n"
        "    reliability: 50\n    stability: 50\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemicPipelineError):
        load_testing_config(path)


def test_live_pipeline_happy_path(live_env):
    stats = run_live_pipeline(make_options(live_env))
    assert stats["status"] == "ok"
    assert stats["candidates_sampled"] == 10
    assert stats["preflight_tested"] == 10
    assert stats["preflight_passed"] + stats["preflight_failure_reasons"].get("dns_failure", 0) == 10
    assert stats["tcp_passed"] == stats["preflight_passed"]  # public compatibility alias
    assert stats["runtime_tested"] <= 5
    assert stats["runtime_live"] == stats["runtime_tested"]
    assert stats["proxy_live"] == stats["runtime_live"]
    assert stats["live_selected"] == stats["runtime_live"]
    assert stats["median_proxy_latency_ms"] == 120.0
    assert stats["scheduler"]["preflight"]["selected"] == 10
    assert stats["scheduler"]["runtime"]["selected"] == stats["runtime_tested"]

    output_dir = live_env["output_dir"]
    assert verify_live_outputs(output_dir) == []
    live_nodes = json.loads((output_dir / "live_nodes.json").read_text(encoding="utf-8"))
    assert all("original_uri" not in node for node in live_nodes)
    assert all("verification" in node for node in live_nodes)
    # Hostname nodes keep resolver observations as diagnostics only. Downstream
    # core stages must not receive the GitHub runner's IP as a forced override.
    assert all(node["resolved_ip"] is None for node in live_nodes)
    assert all(node["preflight_resolved_ip"] for node in live_nodes)


def test_live_pipeline_updates_history(live_env):
    run_live_pipeline(make_options(live_env))
    history = ReliabilityHistory.load(live_env["history_path"])
    # Every discovered node is observed for starvation-free rotation, while
    # selected nodes additionally receive scheduling/outcome counters.
    assert len(history.entries) == len(make_configs())
    assert all(entry.first_discovered for entry in history.entries.values())
    assert any(entry.checks_passed == 1 for entry in history.entries.values())
    assert any(entry.consecutive_failures == 1 for entry in history.entries.values())
    assert any(entry.preflight_scheduled_total >= 1 for entry in history.entries.values())
    assert any(entry.runtime_scheduled_total >= 1 for entry in history.entries.values())


def test_live_pipeline_zero_live_is_not_systemic(live_env, monkeypatch):
    class AllFailEngine(FakeVerificationEngine):
        def runtime(self, candidates):
            results = []
            for item in candidates:
                result = RuntimeVerificationResult(
                    config=item.config,
                    core_started=True,
                    repetitions=1,
                    min_success_ratio=1.0,
                    min_success_count=1,
                    failure_reason="runtime_quorum_failed:network_error=1",
                )
                result.probes = [
                    ApplicationProbeResult(url="x", ok=False, failure_reason="network_error")
                ]
                results.append(result)
            return results, 0

    monkeypatch.setattr(lp, "VerificationEngine", AllFailEngine)
    stats = run_live_pipeline(make_options(live_env))
    assert stats["status"] == "zero_live"
    assert stats["live_selected"] == 0
    assert verify_live_outputs(live_env["output_dir"]) == []


def test_live_pipeline_missing_core_is_systemic(live_env):
    with pytest.raises(SystemicPipelineError):
        run_live_pipeline(make_options(live_env, core_paths={}))


def test_live_pipeline_no_sources_is_systemic(live_env, monkeypatch):
    def zero_sources(options):
        configs, stats = fake_collect_configs(options)
        stats["sources_success"] = 0
        return configs, stats

    monkeypatch.setattr(lp, "collect_configs", zero_sources)
    with pytest.raises(SystemicPipelineError):
        run_live_pipeline(make_options(live_env))


def test_live_pipeline_source_config_error_is_systemic(live_env, monkeypatch):
    monkeypatch.setattr(lp, "collect_configs", lambda options: (_ for _ in ()).throw(SourceConfigError("bad")))
    with pytest.raises(SystemicPipelineError):
        run_live_pipeline(make_options(live_env))


def test_live_pipeline_deadline_excludes_without_failing(live_env, monkeypatch):
    class DeadlineEngine(FakeVerificationEngine):
        def runtime(self, candidates):
            # One starts, the rest are deadline-excluded and must not be failures.
            results, _ = super().runtime(candidates[:1])
            return results, max(0, len(candidates) - 1)

    monkeypatch.setattr(lp, "VerificationEngine", DeadlineEngine)
    stats = run_live_pipeline(make_options(live_env))
    assert stats["runtime_not_tested"] >= 1


def test_live_pipeline_expands_static_ip_candidates_before_preflight(live_env, monkeypatch):
    import copy
    from types import SimpleNamespace

    from auto_subscription_engine.core.models import Endpoint
    from auto_subscription_engine.core.models.fingerprint import compute_canonical_fingerprint
    from auto_subscription_engine.core.network import IpHunterResult

    seen_hosts: list[str] = []

    class CapturingEngine(FakeVerificationEngine):
        def preflight(self, configs):
            seen_hosts.extend(config.host or "" for config in configs)
            return super().preflight(configs)

    class FakeHunter:
        policy = SimpleNamespace(enabled=True)

        def hunt(self, configs):
            base = next(config for config in configs if config.protocol == "trojan")
            variant = copy.deepcopy(base)
            variant.endpoint = Endpoint("8.8.8.8", base.port)
            variant.raw = ""
            variant.fingerprint = compute_canonical_fingerprint(variant)
            return IpHunterResult(variants=[variant], host_inputs=1, current_variants=1)

    monkeypatch.setattr(lp, "VerificationEngine", CapturingEngine)
    monkeypatch.setattr(lp.StaticIpHunter, "from_paths", staticmethod(lambda **kwargs: FakeHunter()))
    hunter_config = live_env["tmp_path"] / "ip_hunter.yaml"
    hunter_config.write_text("enabled: true\n", encoding="utf-8")
    stats = run_live_pipeline(
        make_options(
            live_env,
            ip_hunter_config_path=hunter_config,
            ip_history_path=live_env["tmp_path"] / "ip_history.json",
        )
    )
    assert "8.8.8.8" in seen_hosts
    assert stats["ip_hunter"]["variants_created"] == 1
    live_nodes = json.loads((live_env["output_dir"] / "live_nodes.json").read_text(encoding="utf-8"))
    # A genuine Stage 4 direct-IP candidate keeps the IP in resolved_ip, unlike
    # ordinary hostname nodes whose resolver answer is diagnostic-only.
    assert any(node["resolved_ip"] == "8.8.8.8" for node in live_nodes)


def test_live_pipeline_rotates_preflight_budget_across_runs(live_env):
    run_live_pipeline(make_options(live_env))
    first = ReliabilityHistory.load(live_env["history_path"])
    first_scheduled = {
        fp for fp, entry in first.entries.items() if entry.preflight_scheduled_total > 0
    }
    assert len(first_scheduled) == 10

    run_live_pipeline(make_options(live_env))
    second = ReliabilityHistory.load(live_env["history_path"])
    second_scheduled = {
        fp for fp, entry in second.entries.items() if entry.preflight_scheduled_total > 0
    }
    # The two unscheduled nodes from run 1 are promoted on run 2 before recent
    # candidates repeat, proving rotation at the full pipeline boundary.
    assert second_scheduled == {config.fingerprint for config in make_configs()}
