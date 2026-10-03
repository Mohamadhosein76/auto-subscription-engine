"""Stage 6 scheduler policy loader."""
from __future__ import annotations

from .models import SchedulerPolicy


def policy_from_mapping(raw: dict | None) -> SchedulerPolicy:
    raw = raw if isinstance(raw, dict) else {}
    policy = SchedulerPolicy(
        preflight_budget=int(raw.get("preflight_budget", 1500)),
        runtime_budget=int(raw.get("runtime_budget", 400)),
        exploration_share=float(raw.get("exploration_share", 0.35)),
        recovery_share=float(raw.get("recovery_share", 0.20)),
        direct_ip_share=float(raw.get("direct_ip_share", 0.15)),
        source_base_share=float(raw.get("source_base_share", 0.15)),
        source_quality_bonus_share=float(raw.get("source_quality_bonus_share", 0.20)),
        healthy_retest_minutes=int(raw.get("healthy_retest_minutes", 180)),
        flaky_retest_minutes=int(raw.get("flaky_retest_minutes", 45)),
        exploration_retry_minutes=int(raw.get("exploration_retry_minutes", 60)),
        recovery_base_minutes=int(raw.get("recovery_base_minutes", 30)),
        recovery_max_hours=int(raw.get("recovery_max_hours", 12)),
        stale_after_hours=int(raw.get("stale_after_hours", 24)),
        flaky_success_rate=float(raw.get("flaky_success_rate", 0.75)),
        source_quality_weight=float(raw.get("source_quality_weight", 20.0)),
        direct_ip_bonus=float(raw.get("direct_ip_bonus", 12.0)),
        preflight_latency_bonus=float(raw.get("preflight_latency_bonus", 10.0)),
        allow_early_fill=bool(raw.get("allow_early_fill", True)),
    )
    policy.validate()
    return policy
