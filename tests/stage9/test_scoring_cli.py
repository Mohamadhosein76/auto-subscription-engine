from __future__ import annotations

import json
from pathlib import Path

from auto_subscription_engine.cli import main


def test_verify_score_cli_reports_invalid_directory(tmp_path: Path):
    assert main(["verify-score", "--output-dir", str(tmp_path)]) == 1


def test_score_check_cli_handles_empty_node_set(tmp_path: Path):
    output = tmp_path / "output"
    output.mkdir()
    (output / "live_nodes.json").write_text("[]\n", encoding="utf-8")
    (output / "live_stats.json").write_text(json.dumps({"status": "ok"}) + "\n", encoding="utf-8")
    testing = tmp_path / "testing.yaml"
    testing.write_text("scoring: {}\n", encoding="utf-8")
    history = tmp_path / "history.json"
    history.write_text('{"schema_version": 4, "entries": {}}\n', encoding="utf-8")
    operator_state = tmp_path / "operator.json"
    operator_state.write_text('{"schema_version": 1, "nodes": {}, "processed_result_ids": []}\n', encoding="utf-8")
    operator_cfg = tmp_path / "operator.yaml"
    operator_cfg.write_text("profiles: {}\npolicy: {}\n", encoding="utf-8")
    assert main([
        "score-check", "--output-dir", str(output),
        "--testing-config", str(testing), "--history", str(history),
        "--operator-state", str(operator_state), "--operator-config", str(operator_cfg),
    ]) == 0
    assert main(["verify-score", "--output-dir", str(output)]) == 0
