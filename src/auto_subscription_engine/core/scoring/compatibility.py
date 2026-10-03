"""Core/client portability scoring used by the Stage-7 compatibility layer."""
from __future__ import annotations

from dataclasses import dataclass

from ..clients.compatibility.matrix import CORES, NodeFeatures, protocol_portability


@dataclass
class CompatScoreInput:
    features: NodeFeatures
    cores_passed: frozenset[str]
    cores_applicable: frozenset[str]
    latencies_ms: dict[str, float | None]
    tcp_based: bool
    tls_or_reality: bool
    port_443: bool
    ipv4: bool


def compatibility_score(inp: CompatScoreInput) -> int:
    applicable = inp.cores_applicable or frozenset(inp.cores_passed)
    cores_fraction = len(inp.cores_passed & applicable) / len(applicable) if applicable else 0.0
    portability = protocol_portability(inp.features.protocol)
    resilience = (
        (0.25 if inp.tcp_based else 0.0)
        + (0.25 if inp.tls_or_reality else 0.0)
        + (0.25 if inp.port_443 else 0.0)
        + (0.25 if inp.ipv4 else 0.0)
    )
    values = [
        value for core, value in inp.latencies_ms.items()
        if value is not None and core in inp.cores_passed
    ]
    if len(values) >= 2:
        worst, best = max(values), min(values)
        consistency = 1.0 - min(1.0, (worst - best) / max(worst, 1.0))
    else:
        consistency = 0.75
    return _score(
        40.0 * cores_fraction
        + 20.0 * portability
        + 20.0 * resilience
        + 20.0 * consistency
    )


def worst_core_latency_ms(latencies_ms: dict[str, float | None]) -> float | None:
    values = [value for value in latencies_ms.values() if value is not None]
    return max(values) if values else None


def universal_rank_key(*, compat_score: int, latencies_ms: dict[str, float | None], fingerprint: str) -> tuple:
    worst = worst_core_latency_ms(latencies_ms)
    return (-compat_score, float("inf") if worst is None else worst, fingerprint)


def all_cores() -> tuple[str, ...]:
    return CORES


def _score(value: float) -> int:
    return int(round(min(100.0, max(0.0, value))))
