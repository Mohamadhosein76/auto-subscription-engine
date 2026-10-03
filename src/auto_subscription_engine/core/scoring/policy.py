"""Stage-9 scoring policy and validation."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class WeightSet:
    values: dict[str, float]

    def validate(self, required: tuple[str, ...]) -> None:
        missing = set(required) - set(self.values)
        if missing:
            raise ValueError(f"scoring weights missing keys: {sorted(missing)}")
        total = sum(float(self.values[key]) for key in required)
        if abs(total - 100.0) > 1e-9:
            raise ValueError(f"scoring weights must sum to 100 (got {total})")
        if any(float(self.values[key]) < 0 for key in required):
            raise ValueError("scoring weights cannot be negative")


@dataclass(frozen=True)
class ScoringPolicy:
    latency_min_ms: float = 150.0
    latency_max_ms: float = 3000.0
    min_history_samples: int = 3
    freshness_full_minutes: int = 60
    freshness_zero_minutes: int = 1440
    preselection_weights: WeightSet = field(default_factory=lambda: WeightSet({
        "connectivity": 35.0,
        "latency": 25.0,
        "reliability": 25.0,
        "stability": 15.0,
    }))
    global_weights: WeightSet = field(default_factory=lambda: WeightSet({
        "connectivity": 30.0,
        "latency": 20.0,
        "reliability": 25.0,
        "freshness": 10.0,
        "security": 15.0,
    }))
    operator_weights: WeightSet = field(default_factory=lambda: WeightSet({
        "connectivity": 45.0,
        "reliability": 30.0,
        "latency": 15.0,
        "freshness": 10.0,
    }))
    client_weights: WeightSet = field(default_factory=lambda: WeightSet({
        "runtime": 60.0,
        "reliability": 20.0,
        "latency": 20.0,
    }))

    def validate(self) -> None:
        if self.latency_min_ms < 0 or self.latency_max_ms <= self.latency_min_ms:
            raise ValueError("scoring latency bounds are invalid")
        if self.min_history_samples < 1:
            raise ValueError("scoring min_history_samples must be >= 1")
        if self.freshness_full_minutes < 0:
            raise ValueError("freshness_full_minutes cannot be negative")
        if self.freshness_zero_minutes <= self.freshness_full_minutes:
            raise ValueError("freshness_zero_minutes must exceed freshness_full_minutes")
        self.preselection_weights.validate(("connectivity", "latency", "reliability", "stability"))
        self.global_weights.validate(("connectivity", "latency", "reliability", "freshness", "security"))
        self.operator_weights.validate(("connectivity", "reliability", "latency", "freshness"))
        self.client_weights.validate(("runtime", "reliability", "latency"))

    @classmethod
    def from_mapping(cls, raw: dict | None) -> "ScoringPolicy":
        raw = raw or {}
        old_weights = raw.get("weights") or {}
        preselection = old_weights or raw.get("preselection_weights") or {
            "connectivity": 35.0, "latency": 25.0, "reliability": 25.0, "stability": 15.0,
        }
        policy = cls(
            latency_min_ms=float(raw.get("latency_min_ms", 150.0)),
            latency_max_ms=float(raw.get("latency_max_ms", 3000.0)),
            min_history_samples=int(raw.get("min_history_samples", 3)),
            freshness_full_minutes=int(raw.get("freshness_full_minutes", 60)),
            freshness_zero_minutes=int(raw.get("freshness_zero_minutes", 1440)),
            preselection_weights=WeightSet({k: float(v) for k, v in preselection.items()}),
            global_weights=WeightSet({k: float(v) for k, v in (raw.get("global_weights") or {
                "connectivity": 30.0, "latency": 20.0, "reliability": 25.0,
                "freshness": 10.0, "security": 15.0,
            }).items()}),
            operator_weights=WeightSet({k: float(v) for k, v in (raw.get("operator_weights") or {
                "connectivity": 45.0, "reliability": 30.0, "latency": 15.0, "freshness": 10.0,
            }).items()}),
            client_weights=WeightSet({k: float(v) for k, v in (raw.get("client_weights") or {
                "runtime": 60.0, "reliability": 20.0, "latency": 20.0,
            }).items()}),
        )
        policy.validate()
        return policy
