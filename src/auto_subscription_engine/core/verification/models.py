"""Credential-free verification models used by the live engine.

Stage 5 deliberately separates endpoint reachability from proxy-runtime truth.
An endpoint preflight is only a cheap diagnostic. A node is publishable only
when the real proxy core starts and application traffic succeeds through it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import ParsedConfig


@dataclass(frozen=True)
class AddressAttempt:
    address: str
    family: str  # ipv4 | ipv6
    ok: bool
    latency_ms: float | None = None
    failure_reason: str | None = None


@dataclass
class EndpointPreflightResult:
    config: ParsedConfig
    transport: str = "tcp"  # tcp | udp
    resolved_ips: list[str] = field(default_factory=list)
    selected_ip: str | None = None
    dns_latency_ms: float | None = None
    attempts: list[AddressAttempt] = field(default_factory=list)
    preflight_success: bool = False
    failure_reason: str | None = None
    total_elapsed_ms: float = 0.0

    @property
    def fingerprint(self) -> str:
        return self.config.fingerprint

    @property
    def resolved_ip(self) -> str | None:
        """Compatibility alias for metadata/geo code."""
        return self.selected_ip or (self.resolved_ips[0] if self.resolved_ips else None)

    @property
    def tcp_success(self) -> bool:
        """Compatibility alias; true only when a TCP attempt actually passed."""
        return any(attempt.ok for attempt in self.attempts) if self.transport == "tcp" else False

    @property
    def tcp_latency_ms(self) -> float | None:
        values = [a.latency_ms for a in self.attempts if a.ok and a.latency_ms is not None]
        return min(values) if values else None

    @property
    def ipv4_success(self) -> bool:
        return any(a.ok and a.family == "ipv4" for a in self.attempts)

    @property
    def ipv6_success(self) -> bool:
        return any(a.ok and a.family == "ipv6" for a in self.attempts)


@dataclass
class ApplicationProbeResult:
    url: str
    kind: str = "egress"
    required: bool = True
    round_index: int = 0
    ok: bool = False
    status: int | None = None
    latency_ms: float | None = None
    failure_reason: str | None = None
    body_validated: bool = False


@dataclass
class RuntimeVerificationResult:
    config: ParsedConfig
    mode: str = "native"  # native | pinned-ip
    server_override: str | None = None
    core_started: bool = False
    runtime_core: str | None = None
    attempted_cores: list[str] = field(default_factory=list)
    probes: list[ApplicationProbeResult] = field(default_factory=list)
    repetitions: int = 1
    min_success_ratio: float = 1.0
    min_success_count: int = 1
    min_round_success_ratio: float = 0.0
    success_ratio: float = 0.0
    round_success_ratios: list[float] = field(default_factory=list)
    success_count: int = 0
    proxy_latency_ms: float | None = None
    latency_p95_ms: float | None = None
    jitter_ms: float | None = None
    failure_reason: str | None = None

    @property
    def passed(self) -> bool:
        required = [probe for probe in self.probes if probe.required]
        if not self.core_started or not required:
            return False
        rounds_ok = (
            len(self.round_success_ratios) >= self.repetitions
            and all(
                ratio + 1e-9 >= self.min_round_success_ratio
                for ratio in self.round_success_ratios
            )
        )
        return (
            self.success_count >= self.min_success_count
            and self.success_ratio + 1e-9 >= self.min_success_ratio
            and rounds_ok
        )

    @property
    def fingerprint(self) -> str:
        return self.config.fingerprint


@dataclass
class NodeVerificationResult:
    config: ParsedConfig
    preflight: EndpointPreflightResult | None = None
    runtime: RuntimeVerificationResult | None = None
    score: int = 0
    country_code: str = "UNKNOWN"
    country_name: str = "Unknown"

    # Compatibility alias consumed by existing scoring/output code. Stage 6 can
    # rename that downstream vocabulary without duplicating source logic.
    @property
    def tcp(self) -> EndpointPreflightResult | None:
        return self.preflight

    @property
    def proxy(self) -> RuntimeVerificationResult | None:
        return self.runtime

    @property
    def status(self) -> str:
        if self.runtime is not None and self.runtime.passed:
            return "live"
        if self.runtime is not None:
            return "proxy_failed"
        if self.preflight is not None and self.preflight.preflight_success:
            return "preflight_passed_not_tested"
        if self.preflight is not None:
            return "preflight_failed"
        return "not_tested"

    @property
    def fingerprint(self) -> str:
        return self.config.fingerprint


def median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def percentile(values: list[float], q: float) -> float | None:
    """Small deterministic nearest-rank percentile, q in [0, 1]."""
    if not values:
        return None
    ordered = sorted(float(v) for v in values)
    q = max(0.0, min(1.0, float(q)))
    index = max(0, min(len(ordered) - 1, int(round(q * (len(ordered) - 1)))))
    return ordered[index]


def jitter(values: list[float]) -> float | None:
    """Mean absolute adjacent latency delta; None when fewer than 2 samples."""
    if len(values) < 2:
        return None
    return sum(abs(b - a) for a, b in zip(values, values[1:])) / (len(values) - 1)
