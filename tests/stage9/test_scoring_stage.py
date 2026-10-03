from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from auto_subscription_engine.core.scheduling import ReliabilityHistory
from auto_subscription_engine.core.scoring import ScoringOptions, run_scoring_stage, verify_scoring_outputs
from auto_subscription_engine.core.utils.identity import safe_id


def _write_operator_config(path: Path) -> None:
    path.write_text(
        """schema_version: 1
profiles:
  mci:
    display_name: MCI
    network_type: mobile
    runner_label: ase-mci
    enabled: true
policy:
  stale_after_minutes: 120
""",
        encoding="utf-8",
    )


def _write_testing(path: Path) -> None:
    path.write_text(
        """scoring:
  latency_min_ms: 100
  latency_max_ms: 1000
  min_history_samples: 1
  freshness_full_minutes: 60
  freshness_zero_minutes: 1440
""",
        encoding="utf-8",
    )


def test_scoring_stage_enriches_nodes_without_credentials(tmp_path: Path):
    output = tmp_path / "output"
    output.mkdir()
    fp = "abcdef0123456789"
    sid = safe_id(fp)
    node = {
        "safe_id": sid,
        "protocol": "vless",
        "status": "live",
        "success_ratio": 1.0,
        "proxy_latency_ms": 150.0,
        "verification": {"success_count": 6},
        "security_status": "allow",
        "security_risk_score": 5,
        "security_checks_complete": True,
        "xray_compatible": "pass",
        "hiddify_compatible": "pass",
        "singbox_compatible": "pass",
        "mihomo_compatible": "fail",
        "compat_latency_ms": {"xray": 160.0, "hiddify": 170.0, "singbox": 180.0},
        "score": 77,
    }
    (output / "live_nodes.json").write_text(json.dumps([node]) + "\n", encoding="utf-8")
    (output / "live_stats.json").write_text(json.dumps({"status": "ok"}) + "\n", encoding="utf-8")

    now = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
    history = ReliabilityHistory()
    entry = history.record(fp, passed=True, latency_ms=150.0, timestamp=now.isoformat(timespec="seconds"))
    entry.record_core("xray", passed=True)
    entry.record_core("hiddify", passed=True)
    entry.record_core("singbox", passed=True)
    entry.record_core("mihomo", passed=False)
    history_path = tmp_path / "history.json"
    history.save(history_path)

    operator_state = {
        "schema_version": 1,
        "nodes": {
            fp: {
                "operators": {
                    "mci": {
                        "safe_id": sid,
                        "status": "pass",
                        "success_ratio": 1.0,
                        "latency_p50_ms": 200.0,
                        "last_observed_at": now.isoformat(timespec="seconds"),
                        "checks_total": 2,
                        "checks_passed": 2,
                        "rolling_success_rate": 1.0,
                        "runtime_core": "xray",
                    }
                }
            }
        },
        "processed_result_ids": [],
    }
    operator_state_path = tmp_path / "operators.json"
    operator_state_path.write_text(json.dumps(operator_state) + "\n", encoding="utf-8")
    operator_config = tmp_path / "operators.yaml"
    _write_operator_config(operator_config)
    testing = tmp_path / "testing.yaml"
    _write_testing(testing)

    stats = run_scoring_stage(ScoringOptions(
        output_dir=output, testing_config_path=testing, history_path=history_path,
        operator_state_path=operator_state_path, operator_config_path=operator_config,
        now=now,
    ))
    assert stats["scored_nodes"] == 1
    enriched = json.loads((output / "live_nodes.json").read_text())[0]
    assert enriched["score"] == enriched["scores"]["global"]["score"]
    assert enriched["scores"]["operators"]["mci"]["score"] is not None
    assert enriched["scores"]["clients"]["v2rayng"]["score"] is not None
    assert enriched["scores"]["clients"]["mihomo"]["score"] == 0
    rendered = json.dumps(enriched["scores"])
    assert "://" not in rendered
    assert "password" not in rendered.lower()
    assert verify_scoring_outputs(output) == []


def test_scoring_verifier_rejects_scorecard_mismatch(tmp_path: Path):
    output = tmp_path
    payload = {
        "schema_version": 1,
        "global": {"score": 50, "confidence": 50},
        "connectivity": {"score": 50, "confidence": 50, "evidence_count": 1},
        "latency": {"score": 50, "confidence": 50, "evidence_count": 1},
        "reliability": {"score": 50, "confidence": 50, "evidence_count": 1},
        "freshness": {"score": 50, "confidence": 50, "evidence_count": 1},
        "security": {"score": 50, "confidence": 50, "evidence_count": 1},
        "operators": {}, "clients": {},
    }
    (output / "live_nodes.json").write_text(json.dumps([{"safe_id": "node_x", "score": 50, "scores": payload}]))
    (output / "scorecards.json").write_text(json.dumps({"node_x": {**payload, "global": {"score": 51, "confidence": 50}}}))
    (output / "live_stats.json").write_text(json.dumps({"scoring_v2": {"scored_nodes": 1}}))
    problems = verify_scoring_outputs(output)
    assert any("mismatch" in problem for problem in problems)
