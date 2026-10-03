"""Persistent credential-free operator probe intelligence."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..hardening.state import atomic_write_json, load_json_state
from typing import Any

from .envelope import verify_envelope


def _parse_time(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _contains_sensitive_payload(value: Any) -> bool:
    sensitive_keys = {"uri", "original_uri", "password", "uuid", "token", "secret"}
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in sensitive_keys:
                return True
            if _contains_sensitive_payload(item):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_sensitive_payload(item) for item in value)
    if isinstance(value, str):
        return "://" in value
    return False


class OperatorProbeStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.state = self._load()

    def _load(self) -> dict[str, Any]:
        raw = load_json_state(self.path)
        if raw is None:
            return {"schema_version": 1, "nodes": {}, "processed_result_ids": []}
        if not isinstance(raw, dict):
            raise ValueError("operator probe state has invalid schema")
        raw.setdefault("schema_version", 1)
        raw.setdefault("nodes", {})
        raw.setdefault("processed_result_ids", [])
        if not isinstance(raw["nodes"], dict) or not isinstance(raw["processed_result_ids"], list):
            raise ValueError("operator probe state has invalid shape")
        return raw

    def ingest_signed_result(
        self,
        envelope: dict[str, Any],
        *,
        secret: str,
        expected_operator: str | None = None,
        max_age_minutes: int = 180,
        processed_limit: int = 2000,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        verified = verify_envelope(envelope, expected_kind="probe_result", secret=secret)
        payload = verified.payload
        if int(payload.get("schema_version", 0)) != 1:
            raise ValueError("unsupported operator probe result schema")
        if _contains_sensitive_payload(payload):
            raise ValueError("operator probe result contains sensitive fields")
        operator = str(payload.get("operator_profile", ""))
        if expected_operator is not None and operator != expected_operator:
            raise ValueError("operator profile mismatch")
        result_id = str(payload.get("result_id", ""))
        if not result_id:
            raise ValueError("result_id missing")
        processed = list(self.state.get("processed_result_ids") or [])
        if result_id in processed:
            raise ValueError("replayed operator probe result")
        completed = _parse_time(str(payload.get("completed_at", "")))
        now = now or datetime.now(timezone.utc)
        if completed < now - timedelta(minutes=max(1, int(max_age_minutes))):
            raise ValueError("operator probe result is stale")
        if completed > now + timedelta(minutes=5):
            raise ValueError("operator probe result timestamp is in the future")

        nodes = self.state.setdefault("nodes", {})
        accepted = 0
        for item in payload.get("results") or []:
            if not isinstance(item, dict):
                continue
            fingerprint = str(item.get("fingerprint", ""))
            if not fingerprint:
                continue
            node = nodes.setdefault(fingerprint, {"operators": {}})
            operators = node.setdefault("operators", {})
            previous = operators.get(operator) if isinstance(operators.get(operator), dict) else {}
            checks = int(previous.get("checks_total", 0)) + 1
            passes = int(previous.get("checks_passed", 0)) + (1 if item.get("passed") else 0)
            operators[operator] = {
                "safe_id": str(item.get("safe_id", "")),
                "protocol": str(item.get("protocol", "")),
                "direct_ip": bool(item.get("direct_ip", False)),
                "status": "pass" if item.get("passed") else "fail",
                "runtime_core": item.get("runtime_core"),
                "success_ratio": float(item.get("success_ratio", 0.0) or 0.0),
                "latency_p50_ms": item.get("latency_p50_ms"),
                "latency_p95_ms": item.get("latency_p95_ms"),
                "jitter_ms": item.get("jitter_ms"),
                "failure_reason": item.get("failure_reason"),
                "last_observed_at": str(payload.get("completed_at", "")),
                "probe_id": str(payload.get("probe_id", "")),
                "checks_total": checks,
                "checks_passed": passes,
                "rolling_success_rate": round(passes / checks, 4),
            }
            accepted += 1

        processed.append(result_id)
        self.state["processed_result_ids"] = processed[-max(100, int(processed_limit)):]
        return {"accepted": accepted, "operator_profile": operator, "result_id": result_id}

    def prune(self, *, retention_days: int = 30, max_nodes: int = 50000, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        cutoff = now - timedelta(days=max(1, int(retention_days)))
        nodes = self.state.get("nodes") or {}
        kept: list[tuple[str, dict, datetime]] = []
        for fingerprint, node in nodes.items():
            operators = node.get("operators") if isinstance(node, dict) else None
            latest: datetime | None = None
            if isinstance(operators, dict):
                for item in operators.values():
                    if not isinstance(item, dict) or not item.get("last_observed_at"):
                        continue
                    try:
                        observed = _parse_time(str(item["last_observed_at"]))
                    except (ValueError, TypeError):
                        continue
                    latest = observed if latest is None or observed > latest else latest
            if latest is not None and latest >= cutoff:
                kept.append((fingerprint, node, latest))
        kept.sort(key=lambda row: row[2], reverse=True)
        self.state["nodes"] = {fp: node for fp, node, _ts in kept[: max(100, int(max_nodes))]}

    def save(self) -> None:
        atomic_write_json(self.path, self.state)
