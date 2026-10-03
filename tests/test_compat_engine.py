"""Multi-core compatibility stage tests (offline, scripted fake cores)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
import yaml

from auto_subscription_engine.core.clients.compatibility.engine import (
    CompatOptions,
    apply_feed_diversity,
    run_compat_stage,
)
from auto_subscription_engine.core.clients.compatibility.runner import CoreTestResult
from auto_subscription_engine.core.clients.compatibility.verify import verify_compat_outputs
from auto_subscription_engine.core.models.fingerprint import normalize_config
from auto_subscription_engine.core.protocols import parse_uri
from auto_subscription_engine.core.utils.identity import config_safe_id

VLESS_R = (
    "vless://11111111-2222-3333-4444-555555555555@93.184.216.{n}:443"
    "?security=reality&sni=www.example.org&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"
    "&sid=6ba85179&type=tcp&flow=xtls-rprx-vision#reality-{n}"
)
VLESS_WS = (
    "vless://11111111-2222-3333-4444-555555555555@93.184.216.90:443"
    "?security=tls&sni=tls.example.org&host=ws.example.org&path=%2Fws&type=ws#ws"
)
TROJAN = (
    "trojan://trojanpass@198.51.100.10:443"
    "?security=tls&sni=troj.example.com&type=tcp#trojan"
)
SS = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM=@192.0.2.10:443#ss"
HY2 = "hysteria2://hypass@203.0.113.5:443/?sni=hy2.example.com#hy2"

URIS = [VLESS_R.format(n=n) for n in (1, 2, 3, 4)] + [VLESS_WS, TROJAN, SS, HY2]


def build_output_set(tmp_path: Path, uris: list[str]) -> Path:
    output = tmp_path / "output"
    output.mkdir(parents=True, exist_ok=True)
    entries = []
    for uri in uris:
        config = normalize_config(parse_uri(uri))
        entries.append({
            "safe_id": config_safe_id(config),
            "protocol": config.protocol,
            "status": "live",
            "selected": True,
            "country_code": "US",
            "country_name": "United States",
            "resolved_ip": config.host,
            "tcp_latency_ms": 30.0,
            "proxy_latency_ms": 400.0,
            "success_ratio": 1.0,
            "score": 70,
            "security_status": "allow_with_warnings",
            "security_risk_score": 20,
            "security_reasons": [],
            "security_checks_complete": True,
            "asn": 64512,
            "as_name": "TEST-ASN",
            "prefix": "93.184.216.0/24",
            "source": "test-source",
        })
    (output / "live_subscription.txt").write_text("\n".join(uris) + "\n", encoding="utf-8")
    (output / "live_nodes.json").write_text(json.dumps(entries, indent=2), encoding="utf-8")
    (output / "live_stats.json").write_text(
        json.dumps({"live_total": len(uris), "live_selected": len(uris)}, indent=2),
        encoding="utf-8",
    )
    return output


def scripted_factory(script: dict[str, dict[str, str]]):
    """Build a tester factory: script[core][fingerprint] = 'pass'|'fail'|..."""

    class ScriptedTester:
        def __init__(self, core):
            self.core = core

        def test_node(self, config, resolved_ip=None):
            outcome = script.get(self.core, {}).get(config.fingerprint, "pass")
            if outcome == "pass":
                return CoreTestResult(core=self.core, status="pass", latency_ms=250.0)
            if outcome == "unsupported":
                return CoreTestResult(
                    core=self.core, status="unsupported",
                    failure_category="unsupported_protocol:x",
                )
            return CoreTestResult(
                core=self.core, status="fail",
                failure_category=outcome if ":" in outcome else "core_startup_failed",
            )

        def cleanup(self):
            return None

    def factory(core, binary_path, compat_cfg, test_urls):
        return ScriptedTester(core)

    return factory


def make_options(output: Path, factory) -> CompatOptions:
    testing = Path(__file__).parent.parent / "config" / "testing.yaml"
    core_dir = output.parent / "cores"
    core_dir.mkdir(exist_ok=True)
    core_paths = {}
    for name in ("singbox", "xray", "hiddify", "mihomo"):
        binary = core_dir / name
        binary.write_bytes(b"#!/bin/sh\n")
        binary.chmod(0o755)
        core_paths[name] = binary
    return CompatOptions(
        output_dir=output,
        testing_config_path=testing,
        core_paths=core_paths,
        discovery_state_path=output.parent / "discovery.json",
        tester_factory=factory,
    )


def test_universal_is_multi_core_intersection(tmp_path):
    output = build_output_set(tmp_path, URIS)
    trojan_fp = normalize_config(parse_uri(TROJAN)).fingerprint
    run_compat_stage(make_options(output, scripted_factory({"xray": {trojan_fp: "fail"}})))
    nodes = json.loads((output / "live_nodes.json").read_text(encoding="utf-8"))
    by_id = {row["safe_id"]: row for row in nodes}
    trojan_id = config_safe_id(normalize_config(parse_uri(TROJAN)))
    hy2_id = config_safe_id(normalize_config(parse_uri(HY2)))
    ws_id = config_safe_id(normalize_config(parse_uri(VLESS_WS)))
    assert by_id[trojan_id]["universal_compatible"] is False
    assert by_id[hy2_id]["universal_compatible"] is False
    assert by_id[ws_id]["universal_compatible"] is True
    # Stage 7 no longer rewrites the credential-bearing subscription; Stage 10 owns feeds.
    assert _read_feed(output / "live_subscription.txt") == URIS


def test_v2rayng_evidence_excludes_xray_failures(tmp_path):
    output = build_output_set(tmp_path, URIS)
    trojan_fp = normalize_config(parse_uri(TROJAN)).fingerprint
    run_compat_stage(make_options(output, scripted_factory({"xray": {trojan_fp: "fail"}})))
    nodes = json.loads((output / "live_nodes.json").read_text(encoding="utf-8"))
    by_id = {row["safe_id"]: row for row in nodes}
    assert by_id[config_safe_id(normalize_config(parse_uri(TROJAN)))]["xray_compatible"] == "fail"
    assert by_id[config_safe_id(normalize_config(parse_uri(HY2)))]["xray_compatible"] == "unsupported"
    assert by_id[config_safe_id(normalize_config(parse_uri(SS)))]["xray_compatible"] == "pass"


def test_hiddify_evidence_excludes_hiddify_failures(tmp_path):
    output = build_output_set(tmp_path, URIS)
    ss_fp = normalize_config(parse_uri(SS)).fingerprint
    run_compat_stage(make_options(output, scripted_factory({"hiddify": {ss_fp: "fail"}})))
    nodes = json.loads((output / "live_nodes.json").read_text(encoding="utf-8"))
    by_id = {row["safe_id"]: row for row in nodes}
    assert by_id[config_safe_id(normalize_config(parse_uri(SS)))]["hiddify_compatible"] == "fail"
    assert by_id[config_safe_id(normalize_config(parse_uri(HY2)))]["hiddify_compatible"] == "pass"


def test_mihomo_evidence_is_recorded(tmp_path):
    output = build_output_set(tmp_path, URIS)
    ws_fp = normalize_config(parse_uri(VLESS_WS)).fingerprint
    run_compat_stage(make_options(output, scripted_factory({"mihomo": {ws_fp: "fail"}})))
    nodes = json.loads((output / "live_nodes.json").read_text(encoding="utf-8"))
    by_id = {row["safe_id"]: row for row in nodes}
    assert by_id[config_safe_id(normalize_config(parse_uri(VLESS_WS)))]["mihomo_compatible"] == "fail"
    assert by_id[config_safe_id(normalize_config(parse_uri(HY2)))]["mihomo_compatible"] == "pass"


def test_unavailable_core_suppresses_feed_and_universal(tmp_path):
    output = build_output_set(tmp_path, URIS)
    options = make_options(output, scripted_factory({}))
    options.core_paths["hiddify"] = Path("/nonexistent/hiddify")
    result = run_compat_stage(options)
    assert result.core_statuses["hiddify"] == "unavailable"
    assert result.feed_counts["universal"] == 0
    assert result.feed_counts["hiddify"] == 0
    assert result.feed_counts["v2rayng"] > 0  # xray still available


def test_metadata_and_stats_annotations(tmp_path):
    output = build_output_set(tmp_path, URIS)
    run_compat_stage(make_options(output, scripted_factory({})))

    nodes = json.loads((output / "live_nodes.json").read_text(encoding="utf-8"))
    for entry in nodes:
        for key in (
            "singbox_compatible", "xray_compatible", "hiddify_compatible",
            "mihomo_compatible", "universal_compatible", "compatibility_score",
            "network_profile",
        ):
            assert key in entry, f"missing {key}"
        assert "original_uri" not in entry and "params" not in entry
    stats = json.loads((output / "live_stats.json").read_text(encoding="utf-8"))
    compat = stats["compatibility"]
    for key in (
        "singbox_pass", "xray_tested", "xray_pass", "hiddify_tested",
        "hiddify_pass", "mihomo_tested", "mihomo_pass", "universal_pass",
        "mobile_safe_count", "per_protocol_compatibility", "failure_reasons",
        "median_latency_ms", "core_versions", "source_quality",
    ):
        assert key in compat
    assert stats["universal_count"] == compat["universal_pass"]


def test_network_profiles_are_recorded_for_feed_engine(tmp_path):
    output = build_output_set(tmp_path, URIS)
    run_compat_stage(make_options(output, scripted_factory({})))
    nodes = json.loads((output / "live_nodes.json").read_text(encoding="utf-8"))
    by_id = {row["safe_id"]: row for row in nodes}
    hy2 = by_id[config_safe_id(normalize_config(parse_uri(HY2)))]["network_profile"]
    ss = by_id[config_safe_id(normalize_config(parse_uri(SS)))]["network_profile"]
    assert hy2["udp"] is True and hy2["tcp"] is False
    assert ss["tcp"] is True and ss["udp"] is False
    assert all(row["network_profile"]["port_443"] for row in nodes)


def test_verify_compat_passes_on_valid_evidence(tmp_path):
    output = build_output_set(tmp_path, URIS)
    run_compat_stage(make_options(output, scripted_factory({})))
    assert verify_compat_outputs(output) == []
    assert not (output / "clients").exists()
    assert not (output / "networks").exists()


def test_stage7_does_not_publish_user_feeds(tmp_path):
    output = build_output_set(tmp_path, URIS)
    run_compat_stage(make_options(output, scripted_factory({})))
    assert not (output / "clients").exists()
    assert not (output / "networks").exists()


def test_source_soft_limit_never_empties_feed(tmp_path):
    uris = [VLESS_R.format(n=n) for n in range(1, 7)]
    output = build_output_set(tmp_path, uris)
    meta = {u: {"asn": None, "prefix": None, "host": f"h{i}", "source": "single-source"}
            for i, u in enumerate(uris)}
    # one source for the whole pool: soft limit must NOT hollow it out
    kept = apply_feed_diversity(
        list(uris), meta, per_asn=8, per_prefix=4, per_host=3,
        per_source_soft=0.5, min_keep=3,
    )
    assert len(kept) == len(uris)


def test_source_soft_limit_enforced_with_alternatives(tmp_path):
    uris = [VLESS_R.format(n=n) for n in range(1, 9)]
    output = build_output_set(tmp_path, uris)
    meta = {
        uris[0]: {"asn": None, "prefix": None, "host": f"h0", "source": "a"},
        uris[1]: {"asn": None, "prefix": None, "host": f"h1", "source": "a"},
        uris[2]: {"asn": None, "prefix": None, "host": f"h2", "source": "a"},
        uris[3]: {"asn": None, "prefix": None, "host": f"h3", "source": "a"},
        uris[4]: {"asn": None, "prefix": None, "host": f"h4", "source": "a"},
        uris[5]: {"asn": None, "prefix": None, "host": f"h5", "source": "b"},
        uris[6]: {"asn": None, "prefix": None, "host": f"h6", "source": "b"},
        uris[7]: {"asn": None, "prefix": None, "host": f"h7", "source": "b"},
    }
    kept = apply_feed_diversity(
        list(uris), meta, per_asn=8, per_prefix=4, per_host=8,
        per_source_soft=0.5, min_keep=3,
    )
    sources = {meta[key]["source"] for key in kept}
    assert "b" in sources  # alternatives exist -> soft limit enforced
    assert len(kept) < len(uris)


def test_source_soft_limit_never_collapses_small_alternative_pool(tmp_path):
    """Real-run regression: a 30+1 pool (one alternative-source node) must
    NOT collapse to 2 under the source share limit — trimming requires
    min_feed_nodes alternatives, exactly like every other feed. The main
    subscription (universal feed) is never hollowed out this way."""
    uris = [VLESS_R.format(n=n) for n in range(1, 32)]  # 30 source-a + 1 source-b
    meta = {
        uri: {"asn": None, "prefix": None, "host": f"h{i}", "source": "a"}
        for i, uri in enumerate(uris[:30])
    }
    meta[uris[30]] = {"asn": None, "prefix": None, "host": "h30", "source": "b"}
    kept = apply_feed_diversity(
        list(uris), meta, per_asn=8, per_prefix=4, per_host=3,
        per_source_soft=0.5, min_keep=3,
    )
    assert len(kept) == 31  # one alternative < min_feed_nodes -> no trimming
    sources = {meta[key]["source"] for key in kept}
    assert sources == {"a", "b"}


def _read_feed(path: Path) -> list[str]:
    return [
        line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def test_mobile_safe_udp_share_cap_is_configurable():
    from auto_subscription_engine.core.clients.compatibility.engine import _apply_udp_share_cap
    from auto_subscription_engine.core.clients.compatibility.classify import NetworkProfile

    evaluations = {
        "tcp-a": {"profile": NetworkProfile(tcp=True, udp=False, ipv4=True, ipv6=False, tls=True, reality=False, port_443=True)},
        "tcp-b": {"profile": NetworkProfile(tcp=True, udp=False, ipv4=True, ipv6=False, tls=True, reality=False, port_443=True)},
        "udp-a": {"profile": NetworkProfile(tcp=False, udp=True, ipv4=True, ipv6=False, tls=True, reality=False, port_443=True)},
        "udp-b": {"profile": NetworkProfile(tcp=False, udp=True, ipv4=True, ipv6=False, tls=True, reality=False, port_443=True)},
    }
    ordered = ["tcp-a", "udp-a", "udp-b", "tcp-b"]
    assert _apply_udp_share_cap(ordered, evaluations, 0.0) == ["tcp-a", "tcp-b"]
    assert _apply_udp_share_cap(ordered, evaluations, 0.5) == ordered
