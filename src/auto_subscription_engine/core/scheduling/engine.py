"""Persistent, fair candidate scheduler used by the live pipeline."""
from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from ..models import ParsedConfig
from ..network import is_ip_literal
from .history import HistoryEntry, ReliabilityHistory
from .models import CandidateDecision, CandidateLane, SchedulePlan, SchedulerPolicy


_LANE_BASE = {
    CandidateLane.EXPLORATION: 100.0,
    CandidateLane.STALE: 96.0,
    CandidateLane.RECOVERY: 90.0,
    CandidateLane.FLAKY: 76.0,
    CandidateLane.HEALTHY: 60.0,
}


def _as_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class CandidateScheduler:
    """Choose bounded preflight/runtime work without starvation.

    The algorithm combines five signals:

    * persistent due-times derived from node history,
    * explicit exploration and recovery reserves,
    * direct-IP reserve/bonus for operator-resilient candidates,
    * source-quality weighting with a soft per-source cap, and
    * protocol round-robin so one protocol cannot monopolize a run.

    Candidates that are not selected keep their old ``last_*_scheduled`` value,
    while selected candidates are marked by the caller. This makes never-tested
    pools rotate across hourly runs instead of repeating the same fingerprint
    prefix forever.
    """

    def __init__(
        self,
        *,
        policy: SchedulerPolicy,
        history: ReliabilityHistory,
        source_quality: dict[str, float] | None = None,
        now: datetime | None = None,
    ) -> None:
        policy.validate()
        self.policy = policy
        self.history = history
        self.source_quality = source_quality or {}
        self.now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    def observe(self, configs: Sequence[ParsedConfig]) -> None:
        ts = self.now.isoformat(timespec="seconds")
        for config in configs:
            self.history.observe_candidate(config.fingerprint, timestamp=ts)

    def plan_preflight(
        self,
        configs: Sequence[ParsedConfig],
        *,
        budget: int | None = None,
    ) -> SchedulePlan:
        self.observe(configs)
        actual_budget = max(0, int(self.policy.preflight_budget if budget is None else budget))
        candidates = [(config, config) for config in configs]
        return self._plan(candidates, phase="preflight", budget=actual_budget)

    def plan_runtime(
        self,
        preflight_results: Sequence[Any],
        *,
        budget: int | None = None,
    ) -> SchedulePlan:
        actual_budget = max(0, int(self.policy.runtime_budget if budget is None else budget))
        candidates = [(result, result.config) for result in preflight_results]
        return self._plan(candidates, phase="runtime", budget=actual_budget)

    def mark_selected(self, plan: SchedulePlan) -> None:
        ts = self.now.isoformat(timespec="seconds")
        for item in plan.selected:
            config = self._config_of(item)
            self.history.mark_scheduled(
                config.fingerprint,
                phase=plan.phase,
                timestamp=ts,
            )

    def _plan(
        self,
        candidates: Sequence[tuple[Any, ParsedConfig]],
        *,
        phase: str,
        budget: int,
    ) -> SchedulePlan:
        if budget <= 0 or not candidates:
            return SchedulePlan(selected=[], decisions=[], budget=budget, phase=phase)

        decision_by_fp: dict[str, CandidateDecision] = {}
        item_by_fp: dict[str, Any] = {}
        for item, config in candidates:
            entry = self.history.get(config.fingerprint)
            decision = self._decision(config, entry, phase=phase, item=item)
            decision_by_fp[config.fingerprint] = decision
            item_by_fp[config.fingerprint] = item

        decisions = list(decision_by_fp.values())
        selected_fps: list[str] = []
        source_counts: Counter[str] = Counter()

        exploration_quota = min(
            budget,
            math.ceil(budget * self.policy.exploration_share),
        )
        recovery_quota = min(
            budget,
            math.ceil(budget * self.policy.recovery_share),
        )
        direct_ip_quota = min(
            budget,
            math.ceil(budget * self.policy.direct_ip_share),
        )

        def add_from(pool: list[CandidateDecision], limit: int) -> None:
            if limit <= 0 or len(selected_fps) >= budget:
                return
            picks = self._fair_pick(
                pool,
                limit=min(limit, budget - len(selected_fps)),
                already=set(selected_fps),
                source_counts=source_counts,
                total_budget=budget,
            )
            selected_fps.extend(item.fingerprint for item in picks)

        due = [decision for decision in decisions if decision.due]
        add_from(
            [d for d in due if d.lane == CandidateLane.EXPLORATION],
            exploration_quota,
        )
        add_from(
            [d for d in due if d.lane == CandidateLane.RECOVERY],
            recovery_quota,
        )
        add_from(
            [d for d in due if d.direct_ip],
            direct_ip_quota,
        )
        add_from(due, budget)

        if self.policy.allow_early_fill and len(selected_fps) < budget:
            not_due = [decision for decision in decisions if not decision.due]
            add_from(not_due, budget)

        selected = [item_by_fp[fp] for fp in selected_fps[:budget]]
        return SchedulePlan(
            selected=selected,
            decisions=decisions,
            budget=budget,
            phase=phase,
        )

    def _decision(
        self,
        config: ParsedConfig,
        entry: HistoryEntry | None,
        *,
        phase: str,
        item: Any,
    ) -> CandidateDecision:
        lane = self._lane(entry)
        last_scheduled = self._last_scheduled(entry, phase)
        due_at = self._due_at(entry, lane=lane, phase=phase)
        due = due_at is None or due_at <= self.now
        direct_ip = bool(config.host and is_ip_literal(config.host))
        quality = min(1.0, max(0.0, self.source_quality.get(config.source or "", 0.5)))

        priority = _LANE_BASE[lane]
        if due:
            priority += 25.0
            if due_at is not None:
                overdue_hours = max(0.0, (self.now - due_at).total_seconds() / 3600.0)
                priority += min(20.0, overdue_hours)
        else:
            # Not-due nodes are only considered by early-fill, sorted by the
            # nearest upcoming due time rather than historical score alone.
            until_due = max(0.0, (due_at - self.now).total_seconds() / 3600.0) if due_at else 0.0
            priority -= min(25.0, until_due)

        priority += self.policy.source_quality_weight * quality
        if direct_ip:
            priority += self.policy.direct_ip_bonus

        if phase == "runtime":
            latency = getattr(item, "tcp_latency_ms", None)
            if latency is not None:
                # 0ms -> full bonus, 3000ms+ -> zero bonus.
                latency_factor = max(0.0, 1.0 - min(float(latency), 3000.0) / 3000.0)
                priority += self.policy.preflight_latency_bonus * latency_factor
            if entry is not None and entry.runtime_scheduled_total == 0:
                priority += 30.0

        return CandidateDecision(
            fingerprint=config.fingerprint,
            protocol=config.protocol or "unknown",
            source=config.source or "",
            lane=lane,
            due=due,
            due_at=due_at,
            priority=priority,
            direct_ip=direct_ip,
            source_quality=quality,
            last_scheduled=last_scheduled,
        )

    def _lane(self, entry: HistoryEntry | None) -> CandidateLane:
        if entry is None or entry.checks_total <= 0:
            return CandidateLane.EXPLORATION
        if entry.consecutive_failures > 0:
            return CandidateLane.RECOVERY
        last_seen = _as_utc(entry.last_seen or entry.last_success or entry.last_failure)
        if last_seen is not None and self.now - last_seen >= timedelta(hours=self.policy.stale_after_hours):
            return CandidateLane.STALE
        if entry.rolling_success_rate < self.policy.flaky_success_rate:
            return CandidateLane.FLAKY
        if entry.recent and 0 < sum(entry.recent) < len(entry.recent):
            return CandidateLane.FLAKY
        return CandidateLane.HEALTHY

    def _due_at(
        self,
        entry: HistoryEntry | None,
        *,
        lane: CandidateLane,
        phase: str,
    ) -> datetime | None:
        if entry is None:
            return None
        last_scheduled = self._last_scheduled(entry, phase)
        if lane == CandidateLane.EXPLORATION:
            if last_scheduled is None:
                return None
            return last_scheduled + timedelta(minutes=self.policy.exploration_retry_minutes)
        if lane == CandidateLane.RECOVERY:
            last_failure = _as_utc(entry.last_failure) or _as_utc(entry.last_seen)
            if last_failure is None:
                return None
            exponent = max(0, min(entry.consecutive_failures - 1, 20))
            minutes = min(
                self.policy.recovery_max_hours * 60,
                self.policy.recovery_base_minutes * (2 ** exponent),
            )
            return last_failure + timedelta(minutes=minutes)
        if lane == CandidateLane.FLAKY:
            base = _as_utc(entry.last_seen) or last_scheduled
            return None if base is None else base + timedelta(minutes=self.policy.flaky_retest_minutes)
        if lane == CandidateLane.STALE:
            return None
        base = _as_utc(entry.last_success) or _as_utc(entry.last_seen) or last_scheduled
        return None if base is None else base + timedelta(minutes=self.policy.healthy_retest_minutes)

    @staticmethod
    def _last_scheduled(entry: HistoryEntry | None, phase: str) -> datetime | None:
        if entry is None:
            return None
        value = entry.last_runtime_scheduled if phase == "runtime" else entry.last_preflight_scheduled
        return _as_utc(value)

    def _fair_pick(
        self,
        pool: Sequence[CandidateDecision],
        *,
        limit: int,
        already: set[str],
        source_counts: Counter[str],
        total_budget: int,
    ) -> list[CandidateDecision]:
        if limit <= 0:
            return []
        eligible = [item for item in pool if item.fingerprint not in already]
        if not eligible:
            return []

        def sort_key(item: CandidateDecision) -> tuple:
            # Oldest/never scheduled wins ties. ``datetime.min`` cannot be
            # compared with aware datetimes, so use timestamp seconds.
            last_ts = item.last_scheduled.timestamp() if item.last_scheduled else float("-inf")
            due_ts = item.due_at.timestamp() if item.due_at else float("-inf")
            return (-item.priority, last_ts, due_ts, item.fingerprint)

        by_protocol: dict[str, list[CandidateDecision]] = {}
        for decision in sorted(eligible, key=sort_key):
            by_protocol.setdefault(decision.protocol, []).append(decision)
        protocols = sorted(by_protocol)

        selected: list[CandidateDecision] = []
        # First pass respects adaptive per-source caps. Second pass deliberately
        # relaxes them so a single-source run can still consume its budget.
        for enforce_cap in (True, False):
            while len(selected) < limit:
                took = False
                for protocol in protocols:
                    queue = by_protocol[protocol]
                    chosen_index = None
                    for index, decision in enumerate(queue):
                        if decision.fingerprint in already or any(
                            selected_item.fingerprint == decision.fingerprint for selected_item in selected
                        ):
                            continue
                        if enforce_cap and not self._source_allowed(
                            decision,
                            source_counts=source_counts,
                            total_budget=total_budget,
                        ):
                            continue
                        chosen_index = index
                        break
                    if chosen_index is None:
                        continue
                    decision = queue.pop(chosen_index)
                    selected.append(decision)
                    source_counts[decision.source or "unknown"] += 1
                    took = True
                    if len(selected) >= limit:
                        break
                if not took:
                    break
            if len(selected) >= limit:
                break
        return selected

    def _source_allowed(
        self,
        decision: CandidateDecision,
        *,
        source_counts: Counter[str],
        total_budget: int,
    ) -> bool:
        source = decision.source or "unknown"
        allowed_share = min(
            1.0,
            self.policy.source_base_share
            + self.policy.source_quality_bonus_share * decision.source_quality,
        )
        source_cap = max(1, math.ceil(total_budget * allowed_share))
        return source_counts[source] < source_cap

    @staticmethod
    def _config_of(item: Any) -> ParsedConfig:
        config = getattr(item, "config", None)
        return config if config is not None else item
