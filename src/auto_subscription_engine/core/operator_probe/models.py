"""Credential-free models for operator probe jobs and results."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(frozen=True)
class ProbeCandidate:
    safe_id: str
    fingerprint: str
    uri: str
    protocol: str = ""
    direct_ip: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProbeJob:
    schema_version: int
    job_id: str
    operator_profile: str
    created_at: str
    expires_at: str
    candidates: tuple[ProbeCandidate, ...]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["candidates"] = [candidate.to_dict() for candidate in self.candidates]
        return payload


@dataclass(frozen=True)
class ProbeNodeResult:
    safe_id: str
    fingerprint: str
    protocol: str
    direct_ip: bool
    passed: bool
    runtime_core: str | None
    attempted_cores: tuple[str, ...] = ()
    success_count: int = 0
    success_ratio: float = 0.0
    round_success_ratios: tuple[float, ...] = ()
    latency_p50_ms: float | None = None
    latency_p95_ms: float | None = None
    jitter_ms: float | None = None
    preflight_success: bool = False
    ipv4_success: bool = False
    ipv6_success: bool = False
    failure_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["attempted_cores"] = list(self.attempted_cores)
        payload["round_success_ratios"] = list(self.round_success_ratios)
        return payload


@dataclass(frozen=True)
class ProbeResultBatch:
    schema_version: int
    result_id: str
    job_id: str
    operator_profile: str
    probe_id: str
    started_at: str
    completed_at: str
    agent_version: str
    results: tuple[ProbeNodeResult, ...]
    network: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["results"] = [result.to_dict() for result in self.results]
        return payload
