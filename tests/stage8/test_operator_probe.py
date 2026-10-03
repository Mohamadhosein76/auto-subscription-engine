from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from auto_subscription_engine.core.operator_probe.config import load_operator_probe_config
from auto_subscription_engine.core.operator_probe.envelope import EnvelopeError, sign_payload, verify_envelope
from auto_subscription_engine.core.operator_probe.jobs import build_probe_job
from auto_subscription_engine.core.operator_probe.store import OperatorProbeStore


URI = "vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?security=tls&sni=example.com#x"


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def test_probe_profiles_load():
    cfg = load_operator_probe_config("config/operator_probes.yaml")
    assert set(cfg.profiles) >= {"mci", "irancell", "rightel", "fixed"}
    assert cfg.profiles["mci"].runner_label == "ase-mci"
    assert cfg.policy.max_candidates_per_job == 100


def test_hmac_envelope_roundtrip_and_tamper_rejected():
    payload = {"hello": "world", "n": 1}
    envelope = sign_payload(payload, kind="probe_job", key_id="mci-1", secret="secret")
    verified = verify_envelope(envelope, expected_kind="probe_job", secret="secret")
    assert verified.payload == payload
    envelope["payload_b64"] += "A"
    with pytest.raises(EnvelopeError):
        verify_envelope(envelope, expected_kind="probe_job", secret="secret")


def test_probe_job_is_bounded_deduplicated_and_direct_ip_aware():
    now = datetime(2026, 10, 2, tzinfo=timezone.utc)
    job = build_probe_job(
        [URI, URI],
        operator_profile="mci",
        ttl_minutes=30,
        limit=100,
        now=now,
        job_id="job-1",
    )
    assert job.job_id == "job-1"
    assert len(job.candidates) == 1
    candidate = job.candidates[0]
    assert candidate.fingerprint
    assert candidate.safe_id.startswith("node_")
    assert candidate.direct_ip is True
    assert candidate.protocol == "vless"
    assert job.expires_at == "2026-10-02T00:30:00Z"


def test_store_ingests_signed_result_without_uri_and_rejects_replay(tmp_path):
    now = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
    payload = {
        "schema_version": 1,
        "result_id": "result-1",
        "job_id": "job-1",
        "operator_profile": "mci",
        "probe_id": "mci-home-1",
        "started_at": _iso(now - timedelta(minutes=1)),
        "completed_at": _iso(now),
        "agent_version": "stage8-1",
        "results": [
            {
                "safe_id": "node_abc",
                "fingerprint": "f" * 64,
                "protocol": "vless",
                "direct_ip": True,
                "passed": True,
                "runtime_core": "xray",
                "success_ratio": 1.0,
                "latency_p50_ms": 123.0,
                "latency_p95_ms": 180.0,
                "jitter_ms": 8.0,
                "failure_reason": None,
            }
        ],
    }
    envelope = sign_payload(payload, kind="probe_result", key_id="mci-home-1", secret="secret")
    store = OperatorProbeStore(tmp_path / "operator_probes.json")
    summary = store.ingest_signed_result(
        envelope, secret="secret", expected_operator="mci", now=now
    )
    assert summary["accepted"] == 1
    store.save()
    text = (tmp_path / "operator_probes.json").read_text()
    assert "://" not in text
    state = json.loads(text)
    record = state["nodes"]["f" * 64]["operators"]["mci"]
    assert record["status"] == "pass"
    assert record["runtime_core"] == "xray"
    assert record["rolling_success_rate"] == 1.0
    with pytest.raises(ValueError, match="replayed"):
        store.ingest_signed_result(envelope, secret="secret", expected_operator="mci", now=now)


def test_store_rejects_stale_or_wrong_operator_result(tmp_path):
    now = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
    payload = {
        "schema_version": 1,
        "result_id": "result-old",
        "job_id": "job-1",
        "operator_profile": "irancell",
        "probe_id": "p1",
        "started_at": _iso(now - timedelta(hours=5)),
        "completed_at": _iso(now - timedelta(hours=4)),
        "agent_version": "stage8-1",
        "results": [],
    }
    envelope = sign_payload(payload, kind="probe_result", key_id="p1", secret="secret")
    store = OperatorProbeStore(tmp_path / "operator_probes.json")
    with pytest.raises(ValueError, match="operator profile mismatch"):
        store.ingest_signed_result(envelope, secret="secret", expected_operator="mci", now=now)
    with pytest.raises(ValueError, match="stale"):
        store.ingest_signed_result(
            envelope, secret="secret", expected_operator="irancell", now=now, max_age_minutes=60
        )


def test_operator_matrix_marks_stale_without_deleting_history():
    from auto_subscription_engine.core.operator_probe.matrix import operator_record

    now = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
    state = {
        "nodes": {
            "f" * 64: {
                "operators": {
                    "mci": {
                        "status": "pass",
                        "last_observed_at": _iso(now - timedelta(minutes=121)),
                    }
                }
            }
        }
    }
    record = operator_record(
        state, "f" * 64, "mci", stale_after_minutes=120, now=now
    )
    assert record is not None
    assert record["status"] == "pass"
    assert record["fresh"] is False
