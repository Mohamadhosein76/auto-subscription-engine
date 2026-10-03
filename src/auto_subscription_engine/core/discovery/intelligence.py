"""Persistent, credential-free source intelligence and quarantine policy."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..hardening.state import atomic_write_json, load_json_state

from .models import SourceDefinition, SourceStats

SCHEMA_VERSION = 1
MAX_SOURCE_ENTRIES = 2048


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat(timespec="seconds")


class SourceIntelligenceStore:
    def __init__(self, entries: dict[str, SourceStats] | None = None) -> None:
        self.entries = entries or {}

    @classmethod
    def load(cls, path: Path | None) -> "SourceIntelligenceStore":
        raw = load_json_state(path)
        if raw is None:
            return cls()
        if not isinstance(raw, dict) or not isinstance(raw.get("sources"), dict):
            raise ValueError("discovery state has invalid schema")
        entries: dict[str, SourceStats] = {}
        if isinstance(raw, dict) and isinstance(raw.get("sources"), dict):
            for source_id, item in raw["sources"].items():
                if not isinstance(item, dict):
                    continue
                try:
                    values = {
                        field: item.get(field)
                        for field in SourceStats.__dataclass_fields__
                        if field in item
                    }
                    values["source_id"] = str(item.get("source_id") or source_id)
                    values["name"] = str(item.get("name") or source_id)
                    values["host"] = str(item.get("host") or "")
                    for key in (
                        "fetch_attempts", "fetch_successes", "consecutive_failures",
                        "bytes_received", "proxies_seen", "unique_proxies",
                        "nested_sources_seen", "parse_issues", "tcp_tested", "tcp_passed",
                        "proxy_tested", "proxy_passed", "compat_tested", "compat_passed",
                        "published",
                    ):
                        values[key] = int(values.get(key) or 0)
                    entries[str(source_id)] = SourceStats(**values)
                except (TypeError, ValueError):
                    continue
        return cls(entries)

    def save(self, path: Path | None) -> None:
        if path is None:
            return
        path = Path(path)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "sources": {
                source_id: asdict(entry)
                for source_id, entry in sorted(self.entries.items())
            },
        }
        atomic_write_json(path, payload)

    def get(self, source_id: str) -> SourceStats | None:
        return self.entries.get(source_id)

    def quality(self, source_id: str) -> float:
        entry = self.get(source_id)
        return entry.quality() if entry else 0.5

    def ensure(self, source: SourceDefinition) -> SourceStats:
        entry = self.entries.get(source.source_id)
        if entry is None:
            from urllib.parse import urlsplit
            entry = SourceStats(
                source_id=source.source_id,
                name=source.name,
                host=(urlsplit(source.url).hostname or "").lower(),
            )
            self.entries[source.source_id] = entry
        else:
            entry.name = source.name
        self._bound()
        return entry

    def record_fetch(
        self,
        source: SourceDefinition,
        *,
        ok: bool,
        byte_count: int = 0,
        proxies_seen: int = 0,
        unique_proxies: int = 0,
        nested_sources: int = 0,
        parse_issues: int = 0,
        quarantine_after_failures: int = 3,
        quarantine_base_minutes: int = 30,
        quarantine_max_hours: int = 24,
    ) -> SourceStats:
        entry = self.ensure(source)
        now = _now()
        entry.fetch_attempts += 1
        entry.last_seen = _iso(now)
        if ok:
            entry.fetch_successes += 1
            entry.consecutive_failures = 0
            entry.last_success = entry.last_seen
            entry.quarantined_until = None
            entry.bytes_received += max(0, int(byte_count))
            entry.proxies_seen += max(0, int(proxies_seen))
            entry.unique_proxies += max(0, int(unique_proxies))
            entry.nested_sources_seen += max(0, int(nested_sources))
            entry.parse_issues += max(0, int(parse_issues))
        else:
            entry.consecutive_failures += 1
            entry.last_failure = entry.last_seen
            if entry.consecutive_failures >= max(1, quarantine_after_failures):
                multiplier = 2 ** (entry.consecutive_failures - quarantine_after_failures)
                minutes = min(
                    quarantine_max_hours * 60,
                    quarantine_base_minutes * multiplier,
                )
                entry.quarantined_until = _iso(now + timedelta(minutes=minutes))
        return entry

    def record_verification(
        self,
        source_id: str,
        *,
        tcp_tested: int = 0,
        tcp_passed: int = 0,
        proxy_tested: int = 0,
        proxy_passed: int = 0,
        compat_tested: int = 0,
        compat_passed: int = 0,
        published: int = 0,
    ) -> None:
        entry = self.entries.get(source_id)
        if entry is None:
            return
        entry.tcp_tested += max(0, int(tcp_tested))
        entry.tcp_passed += max(0, int(tcp_passed))
        entry.proxy_tested += max(0, int(proxy_tested))
        entry.proxy_passed += max(0, int(proxy_passed))
        entry.compat_tested += max(0, int(compat_tested))
        entry.compat_passed += max(0, int(compat_passed))
        entry.published += max(0, int(published))
        entry.last_seen = _iso()

    def quality_by_name(self) -> dict[str, float]:
        """Learned quality keyed by stable human source name for pipeline use."""
        return {entry.name: entry.quality() for entry in self.entries.values()}

    def source_id_by_name(self, name: str) -> str | None:
        candidates = [entry for entry in self.entries.values() if entry.name == name]
        if not candidates:
            return None
        candidates.sort(key=lambda item: (item.last_seen or "", item.source_id), reverse=True)
        return candidates[0].source_id

    def record_verification_by_name(self, name: str, **metrics: int) -> None:
        source_id = self.source_id_by_name(name)
        if source_id is not None:
            self.record_verification(source_id, **metrics)

    def summary(self) -> list[dict[str, object]]:
        return [
            {
                "source_id": entry.source_id,
                "source": entry.name,
                "host": entry.host,
                "quality": round(entry.quality(), 3),
                "fetch_success_rate": round(entry.fetch_success_rate(), 3),
                "verification_rate": round(entry.verification_rate(), 3),
                "productivity": round(entry.productivity(), 3),
                "proxies_seen": entry.proxies_seen,
                "unique_proxies": entry.unique_proxies,
                "proxy_passed": entry.proxy_passed,
                "published": entry.published,
                "quarantined": entry.is_quarantined(),
                "quarantined_until": entry.quarantined_until,
            }
            for entry in sorted(self.entries.values(), key=lambda item: (-item.quality(), item.name))
        ]

    def _bound(self) -> None:
        if len(self.entries) <= MAX_SOURCE_ENTRIES:
            return
        ordered = sorted(
            self.entries.values(),
            key=lambda item: (item.last_seen or "", item.source_id),
        )
        for item in ordered[: len(self.entries) - MAX_SOURCE_ENTRIES]:
            self.entries.pop(item.source_id, None)
