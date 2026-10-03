"""Candidate scheduling models for Stage 6.

The scheduler never stores proxy credentials or raw URIs.  It operates on
credential-free fingerprints plus outcome/source metadata and returns a bounded,
deterministic work plan.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class CandidateLane(StrEnum):
    """Behavioral lane used to allocate scheduler budget."""

    EXPLORATION = "exploration"
    RECOVERY = "recovery"
    FLAKY = "flaky"
    HEALTHY = "healthy"
    STALE = "stale"


@dataclass(frozen=True)
class SchedulerPolicy:
    """Bounded adaptive scheduling policy.

    ``preflight_budget`` and ``runtime_budget`` are safety ceilings, not
    deterministic prefix sizes.  Inside those ceilings, persistent history,
    due-time cadence, source quality and fairness decide who gets tested.
    """

    preflight_budget: int = 1500
    runtime_budget: int = 400
    exploration_share: float = 0.35
    recovery_share: float = 0.20
    direct_ip_share: float = 0.15
    source_base_share: float = 0.15
    source_quality_bonus_share: float = 0.20
    healthy_retest_minutes: int = 180
    flaky_retest_minutes: int = 45
    exploration_retry_minutes: int = 60
    recovery_base_minutes: int = 30
    recovery_max_hours: int = 12
    stale_after_hours: int = 24
    flaky_success_rate: float = 0.75
    source_quality_weight: float = 20.0
    direct_ip_bonus: float = 12.0
    preflight_latency_bonus: float = 10.0
    allow_early_fill: bool = True

    def validate(self) -> None:
        if self.preflight_budget <= 0 or self.runtime_budget <= 0:
            raise ValueError("scheduler budgets must be positive")
        for name, value in (
            ("exploration_share", self.exploration_share),
            ("recovery_share", self.recovery_share),
            ("direct_ip_share", self.direct_ip_share),
            ("source_base_share", self.source_base_share),
            ("source_quality_bonus_share", self.source_quality_bonus_share),
            ("flaky_success_rate", self.flaky_success_rate),
        ):
            if not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"scheduler {name} must be in [0, 1]")
        if self.exploration_share + self.recovery_share > 1.0 + 1e-9:
            raise ValueError("scheduler exploration_share + recovery_share must be <= 1")
        if self.recovery_base_minutes <= 0 or self.recovery_max_hours <= 0:
            raise ValueError("scheduler recovery backoff must be positive")
        if self.healthy_retest_minutes <= 0 or self.flaky_retest_minutes <= 0:
            raise ValueError("scheduler retest intervals must be positive")
        if self.exploration_retry_minutes <= 0 or self.stale_after_hours <= 0:
            raise ValueError("scheduler discovery/stale intervals must be positive")
        for name, value in (
            ("source_quality_weight", self.source_quality_weight),
            ("direct_ip_bonus", self.direct_ip_bonus),
            ("preflight_latency_bonus", self.preflight_latency_bonus),
        ):
            if float(value) < 0.0:
                raise ValueError(f"scheduler {name} must be non-negative")


@dataclass(frozen=True)
class CandidateDecision:
    """Credential-free scheduler decision for one candidate."""

    fingerprint: str
    protocol: str
    source: str
    lane: CandidateLane
    due: bool
    due_at: datetime | None
    priority: float
    direct_ip: bool
    source_quality: float
    last_scheduled: datetime | None


@dataclass
class SchedulePlan:
    """Selected work plus aggregate diagnostics."""

    selected: list[Any] = field(default_factory=list)
    decisions: list[CandidateDecision] = field(default_factory=list)
    budget: int = 0
    phase: str = "preflight"

    def summary(self) -> dict[str, object]:
        selected_fps = {
            getattr(item, "fingerprint", None)
            or getattr(getattr(item, "config", None), "fingerprint", None)
            for item in self.selected
        }
        selected_decisions = [
            decision for decision in self.decisions if decision.fingerprint in selected_fps
        ]
        by_lane: dict[str, int] = {}
        by_protocol: dict[str, int] = {}
        by_source: dict[str, int] = {}
        due_selected = 0
        direct_ip_selected = 0
        for decision in selected_decisions:
            by_lane[decision.lane.value] = by_lane.get(decision.lane.value, 0) + 1
            by_protocol[decision.protocol] = by_protocol.get(decision.protocol, 0) + 1
            source = decision.source or "unknown"
            by_source[source] = by_source.get(source, 0) + 1
            due_selected += int(decision.due)
            direct_ip_selected += int(decision.direct_ip)
        return {
            "phase": self.phase,
            "budget": self.budget,
            "candidates_considered": len(self.decisions),
            "selected": len(self.selected),
            "due_candidates": sum(int(item.due) for item in self.decisions),
            "due_selected": due_selected,
            "early_fill_selected": max(0, len(self.selected) - due_selected),
            "direct_ip_selected": direct_ip_selected,
            "selected_by_lane": dict(sorted(by_lane.items())),
            "selected_by_protocol": dict(sorted(by_protocol.items())),
            "selected_by_source": dict(sorted(by_source.items())),
        }
