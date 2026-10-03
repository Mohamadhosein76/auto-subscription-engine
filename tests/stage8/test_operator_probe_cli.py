from __future__ import annotations

import json
from datetime import datetime, timezone

from auto_subscription_engine.cli import main
from auto_subscription_engine.core.operator_probe.envelope import sign_payload, verify_envelope

URI = "vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?security=tls&sni=example.com#x"


def test_cli_builds_signed_probe_job(tmp_path, monkeypatch):
    candidates = tmp_path / "candidates.txt"
    candidates.write_text(URI + "\n", encoding="utf-8")
    output = tmp_path / "job.json"
    monkeypatch.setenv("ASE_OPERATOR_PROBE_SECRET", "secret")
    rc = main([
        "operator-probe-job",
        "--input", str(candidates),
        "--operator-profile", "mci",
        "--output", str(output),
        "--limit", "1",
    ])
    assert rc == 0
    env = json.loads(output.read_text())
    payload = verify_envelope(env, expected_kind="probe_job", secret="secret").payload
    assert payload["operator_profile"] == "mci"
    assert len(payload["candidates"]) == 1
    assert payload["candidates"][0]["fingerprint"]


def test_cli_ingests_signed_result(tmp_path, monkeypatch):
    monkeypatch.setenv("ASE_OPERATOR_PROBE_SECRET", "secret")
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {
        "schema_version": 1,
        "result_id": "result-cli",
        "job_id": "job-cli",
        "operator_profile": "mci",
        "probe_id": "mci-test",
        "started_at": now,
        "completed_at": now,
        "agent_version": "stage8-1",
        "results": [{
            "safe_id": "node_abc",
            "fingerprint": "a" * 64,
            "protocol": "vless",
            "direct_ip": False,
            "passed": True,
            "runtime_core": "xray",
            "success_ratio": 1.0,
        }],
    }
    signed = sign_payload(payload, kind="probe_result", key_id="mci-test", secret="secret")
    result_file = tmp_path / "result.json"
    result_file.write_text(json.dumps(signed), encoding="utf-8")
    state = tmp_path / "state.json"
    rc = main([
        "operator-probe-ingest",
        "--input", str(result_file),
        "--operator-profile", "mci",
        "--state", str(state),
    ])
    assert rc == 0
    saved = json.loads(state.read_text())
    assert saved["nodes"]["a" * 64]["operators"]["mci"]["status"] == "pass"
