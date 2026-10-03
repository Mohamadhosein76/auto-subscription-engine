"""Operator probe profile and policy configuration."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class OperatorProfile:
    key: str
    display_name: str
    network_type: str
    runner_label: str
    enabled: bool = True


@dataclass(frozen=True)
class OperatorProbePolicy:
    job_ttl_minutes: int = 30
    max_candidates_per_job: int = 100
    result_max_age_minutes: int = 180
    stale_after_minutes: int = 120
    history_retention_days: int = 30
    max_nodes: int = 50000
    processed_result_ids: int = 2000


@dataclass(frozen=True)
class OperatorProbeConfig:
    profiles: dict[str, OperatorProfile]
    policy: OperatorProbePolicy


def load_operator_probe_config(path: Path) -> OperatorProbeConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    profiles_raw = raw.get("profiles") or {}
    profiles: dict[str, OperatorProfile] = {}
    for key, item in profiles_raw.items():
        if not isinstance(item, dict):
            continue
        profiles[str(key)] = OperatorProfile(
            key=str(key),
            display_name=str(item.get("display_name", key)),
            network_type=str(item.get("network_type", "unknown")),
            runner_label=str(item.get("runner_label", f"ase-{key}")),
            enabled=bool(item.get("enabled", True)),
        )
    p = raw.get("policy") or {}
    policy = OperatorProbePolicy(
        job_ttl_minutes=max(1, int(p.get("job_ttl_minutes", 30))),
        max_candidates_per_job=max(1, int(p.get("max_candidates_per_job", 100))),
        result_max_age_minutes=max(1, int(p.get("result_max_age_minutes", 180))),
        stale_after_minutes=max(1, int(p.get("stale_after_minutes", 120))),
        history_retention_days=max(1, int(p.get("history_retention_days", 30))),
        max_nodes=max(100, int(p.get("max_nodes", 50000))),
        processed_result_ids=max(100, int(p.get("processed_result_ids", 2000))),
    )
    return OperatorProbeConfig(profiles=profiles, policy=policy)
