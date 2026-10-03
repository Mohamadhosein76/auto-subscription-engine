from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from auto_subscription_engine.core.models.fingerprint import normalize_config
from auto_subscription_engine.core.protocols.registry import parse_uri
from auto_subscription_engine.core.operator_probe import worker
from auto_subscription_engine.core.verification.models import EndpointPreflightResult, RuntimeVerificationResult

URI = "vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?security=tls&sni=example.com#x"


def _job():
    config = normalize_config(parse_uri(URI))
    now = datetime.now(timezone.utc)
    return {
        "schema_version": 1,
        "job_id": "job-1",
        "operator_profile": "mci",
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
        "candidates": [{
            "safe_id": "node_x",
            "fingerprint": config.fingerprint,
            "uri": URI,
            "protocol": "vless",
            "direct_ip": True,
        }],
    }


class FakeEngine:
    def __init__(self, core_paths, policy):
        self.core_paths = core_paths
        self.policy = policy

    def preflight(self, configs):
        return [EndpointPreflightResult(
            config=configs[0],
            preflight_success=True,
            selected_ip="1.1.1.1",
        )]

    def runtime(self, candidates):
        config = candidates[0].config
        result = RuntimeVerificationResult(
            config=config,
            core_started=True,
            runtime_core="xray",
            attempted_cores=["xray"],
            repetitions=1,
            min_success_ratio=1.0,
            min_success_count=1,
            min_round_success_ratio=1.0,
            success_count=1,
            success_ratio=1.0,
            round_success_ratios=[1.0],
            proxy_latency_ms=100.0,
            latency_p95_ms=120.0,
            jitter_ms=5.0,
        )
        # RuntimeVerificationResult.passed also requires at least one required probe.
        from auto_subscription_engine.core.verification.models import ApplicationProbeResult
        result.probes.append(ApplicationProbeResult(url="https://example.com", required=True, ok=True))
        return [result], 0


def test_worker_reuses_central_verification_and_returns_credential_free_payload(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "verified_core_paths", lambda _dir, _cfg: {"xray": tmp_path / "xray"})
    monkeypatch.setattr(worker, "VerificationEngine", FakeEngine)
    testing = tmp_path / "testing.yaml"
    testing.write_text("verification:\n  targets:\n    - url: https://example.com\n", encoding="utf-8")
    payload = worker.execute_job(
        _job(),
        core_dir=tmp_path,
        testing_config=testing,
        probe_id="mci-test",
        operator_profile="mci",
    )
    assert payload["operator_profile"] == "mci"
    assert payload["probe_id"] == "mci-test"
    assert payload["results"][0]["passed"] is True
    assert payload["results"][0]["runtime_core"] == "xray"
    assert "uri" not in payload["results"][0]
    assert "://" not in str(payload["results"])


def test_worker_rejects_fingerprint_tamper(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "verified_core_paths", lambda _dir, _cfg: {"xray": tmp_path / "xray"})
    testing = tmp_path / "testing.yaml"
    testing.write_text("verification:\n  targets:\n    - url: https://example.com\n", encoding="utf-8")
    job = _job()
    job["candidates"][0]["fingerprint"] = "0" * 64
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        worker.execute_job(
            job,
            core_dir=tmp_path,
            testing_config=testing,
            probe_id="mci-test",
            operator_profile="mci",
        )
