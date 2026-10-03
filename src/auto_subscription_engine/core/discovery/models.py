"""Canonical data models for source discovery and source intelligence."""
from __future__ import annotations

from dataclasses import dataclass, field
import math
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class SourceOrigin(StrEnum):
    CONFIG = "config"
    NESTED = "nested"


@dataclass(frozen=True)
class SourceDefinition:
    """One fetchable subscription source.

    ``url`` lives only in the active discovery graph. Persisted intelligence
    stores only a digest + host so query tokens can never leak to git.
    """

    name: str
    url: str
    enabled: bool = True
    priority: int = 50
    tags: tuple[str, ...] = ()
    origin: SourceOrigin = SourceOrigin.CONFIG
    depth: int = 0
    parent_id: str | None = None
    source_id: str = ""


@dataclass(frozen=True)
class FetchOutcome:
    source: SourceDefinition
    ok: bool = False
    status_code: int | None = None
    error: str | None = None
    content: str | None = None
    byte_count: int = 0
    elapsed_ms: float | None = None


@dataclass
class SourceStats:
    """Persisted credential-free source intelligence."""

    source_id: str
    name: str
    host: str
    fetch_attempts: int = 0
    fetch_successes: int = 0
    consecutive_failures: int = 0
    bytes_received: int = 0
    proxies_seen: int = 0
    unique_proxies: int = 0
    nested_sources_seen: int = 0
    parse_issues: int = 0
    tcp_tested: int = 0
    tcp_passed: int = 0
    proxy_tested: int = 0
    proxy_passed: int = 0
    compat_tested: int = 0
    compat_passed: int = 0
    published: int = 0
    last_seen: str | None = None
    last_success: str | None = None
    last_failure: str | None = None
    quarantined_until: str | None = None

    def fetch_success_rate(self) -> float:
        if self.fetch_attempts <= 0:
            return 0.5
        return self.fetch_successes / self.fetch_attempts

    def unique_ratio(self) -> float:
        if self.proxies_seen <= 0:
            return 0.5
        return min(1.0, self.unique_proxies / max(self.proxies_seen, 1))

    def parse_health(self) -> float:
        total = self.proxies_seen + self.parse_issues
        if total <= 0:
            return 0.5
        return self.proxies_seen / total

    def verification_rate(self) -> float:
        proxy_rate = (self.proxy_passed / self.proxy_tested) if self.proxy_tested > 0 else None
        compat_rate = (self.compat_passed / self.compat_tested) if self.compat_tested > 0 else None
        if proxy_rate is not None and compat_rate is not None:
            return 0.65 * proxy_rate + 0.35 * compat_rate
        if proxy_rate is not None:
            return proxy_rate
        if compat_rate is not None:
            return compat_rate
        if self.tcp_tested > 0:
            return self.tcp_passed / self.tcp_tested
        return 0.5

    def productivity(self) -> float:
        """Bounded yield signal; 500 unique proxies is effectively full credit."""
        if self.unique_proxies <= 0:
            return 0.0 if self.fetch_attempts > 0 else 0.5
        return min(1.0, math.log1p(self.unique_proxies) / math.log1p(500))

    def quality(self) -> float:
        """0..1 learned quality, dominated by actual verification outcomes."""
        value = (
            0.25 * self.fetch_success_rate()
            + 0.10 * self.unique_ratio()
            + 0.10 * self.parse_health()
            + 0.45 * self.verification_rate()
            + 0.10 * self.productivity()
        )
        return min(1.0, max(0.0, value))

    def is_quarantined(self, now: datetime | None = None) -> bool:
        if not self.quarantined_until:
            return False
        try:
            until = datetime.fromisoformat(self.quarantined_until)
        except ValueError:
            return False
        now = now or datetime.now(timezone.utc)
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        return until > now


@dataclass(frozen=True)
class DiscoveryPolicy:
    max_depth: int = 2
    max_sources: int = 64
    max_nested_per_source: int = 16
    max_total_proxies: int = 50000
    fetch_concurrency: int = 8
    quarantine_after_failures: int = 3
    quarantine_base_minutes: int = 30
    quarantine_max_hours: int = 24


@dataclass
class SourceReport:
    source_id: str
    name: str
    host: str
    depth: int
    origin: str
    ok: bool
    status_code: int | None
    error: str | None
    byte_count: int
    proxies_found: int
    unique_proxies: int
    nested_sources_found: int
    issues: int
    quality_before: float
    quality_after: float
    skipped_reason: str | None = None


@dataclass
class DiscoveryResult:
    proxies: list[Any] = field(default_factory=list)
    nested_sources: list[SourceDefinition] = field(default_factory=list)
    reports: list[SourceReport] = field(default_factory=list)
    provenance: dict[str, set[str]] = field(default_factory=dict)
    sources_total: int = 0
    sources_fetched: int = 0
    sources_success: int = 0
    sources_failed: int = 0
    sources_quarantined: int = 0
    duplicates_removed: int = 0
