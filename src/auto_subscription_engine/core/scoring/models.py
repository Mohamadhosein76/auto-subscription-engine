"""Credential-free multidimensional score models for Stage 9."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DimensionScore:
    """One bounded score plus evidence quality metadata."""

    score: int | None
    confidence: int = 0
    status: str | None = None
    fresh: bool | None = None
    evidence_count: int = 0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "score": self.score,
            "confidence": _clamp_int(self.confidence),
            "evidence_count": max(0, int(self.evidence_count)),
        }
        if self.status is not None:
            payload["status"] = str(self.status)
        if self.fresh is not None:
            payload["fresh"] = bool(self.fresh)
        if self.details:
            payload["details"] = dict(self.details)
        return payload


@dataclass(frozen=True)
class NodeScoreCard:
    """Complete Stage-9 scorecard for one safe node identifier."""

    global_score: int
    global_confidence: int
    connectivity: DimensionScore
    latency: DimensionScore
    reliability: DimensionScore
    freshness: DimensionScore
    security: DimensionScore
    operators: dict[str, DimensionScore] = field(default_factory=dict)
    clients: dict[str, DimensionScore] = field(default_factory=dict)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "global": {
                "score": _clamp_int(self.global_score),
                "confidence": _clamp_int(self.global_confidence),
            },
            "connectivity": self.connectivity.to_dict(),
            "latency": self.latency.to_dict(),
            "reliability": self.reliability.to_dict(),
            "freshness": self.freshness.to_dict(),
            "security": self.security.to_dict(),
            "operators": {
                key: value.to_dict() for key, value in sorted(self.operators.items())
            },
            "clients": {
                key: value.to_dict() for key, value in sorted(self.clients.items())
            },
        }


def _clamp_int(value: int | float) -> int:
    return int(round(min(100.0, max(0.0, float(value)))))
