"""Reliability history per node fingerprint.

The history answers one question for scoring: *how has this endpoint
behaved across repeated checks?* It stores only fingerprints and outcome
statistics — never credentials, URIs or display names.

File format (``data/history.json`` by default):

.. code-block:: json

    {
      "schema_version": 1,
      "entries": {
        "<fingerprint>": {
          "fingerprint": "...",
          "checks_total": 4,
          "checks_passed": 3,
          "consecutive_successes": 2,
          "consecutive_failures": 0,
          "last_success": "2026-09-29T09:00:00+00:00",
          "last_failure": "2026-09-27T09:00:00+00:00",
          "last_latency_ms": 412.5,
          "rolling_success_rate": 0.75,
          "recent": [1, 1, 0, 1]
        }
      }
    }

``recent`` holds the last ``MAX_RECENT`` outcomes (1 = pass, 0 = fail),
which is what ``rolling_success_rate`` is computed from. Persistence is
atomic (temp file + rename) so a crash never truncates the file, the
serialization is deterministic (sorted keys, fixed indent) so the file is
stable across runs.  Stage 11 hardening keeps a last-known-good backup; an
unreadable primary is recovered from that backup or fails closed rather than
silently resetting reliability state.

Task 3 adds: a ``last_seen`` timestamp per entry, pruning (retention by
days + hard cap on entry count) so the file can never grow unbounded, and
a strict no-secrets guarantee — only fingerprints and metrics are stored,
never URIs, UUIDs, passwords or tokens. The file lives at
``data/history.json``, is committed to ``main`` by the GitHub Action and
therefore persists between scheduled runs.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..hardening.state import atomic_write_json, load_json_state

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 4
MAX_RECENT = 20
MAX_CORE_KEYS = 8


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class HistoryEntry:
    """Outcome statistics for one node fingerprint.

    Every field is a metric or a timestamp — never a credential. The
    fingerprint is a SHA-256 prefix of the node config, so the entry
    cannot be turned back into a usable proxy URI.
    """

    fingerprint: str
    checks_total: int = 0
    checks_passed: int = 0
    consecutive_successes: int = 0
    consecutive_failures: int = 0
    last_success: str | None = None
    last_failure: str | None = None
    last_latency_ms: float | None = None
    rolling_success_rate: float = 0.0
    recent: list[int] = field(default_factory=list)
    last_seen: str | None = None
    # Stage 6 scheduling intelligence. These fields are credential-free and
    # exist solely to guarantee fair rotation and bounded retest cadence.
    first_discovered: str | None = None
    last_discovered: str | None = None
    preflight_scheduled_total: int = 0
    runtime_scheduled_total: int = 0
    last_preflight_scheduled: str | None = None
    last_runtime_scheduled: str | None = None
    #: Per-core reliability (multi-core layer): {"xray": {"checks": 10,
    #: "passed": 8}, ...}. Bounded to MAX_CORE_KEYS keys; only outcome
    #: counters - never credentials.
    cores: dict[str, dict[str, int]] = field(default_factory=dict)

    def recompute_rolling(self) -> None:
        if self.recent:
            self.rolling_success_rate = sum(self.recent) / len(self.recent)
        else:
            self.rolling_success_rate = 0.0

    def record_core(self, core: str, *, passed: bool) -> None:
        """Record one per-core outcome (bounded, deterministic)."""
        bucket = self.cores.setdefault(str(core), {"checks": 0, "passed": 0})
        bucket["checks"] += 1
        if passed:
            bucket["passed"] += 1
        if len(self.cores) > MAX_CORE_KEYS:
            # Deterministic eviction of the lexicographically largest key.
            for key in sorted(self.cores)[MAX_CORE_KEYS:]:
                del self.cores[key]



class ReliabilityHistory:
    """In-memory history with optional JSON file persistence."""

    def __init__(
        self,
        entries: dict[str, HistoryEntry] | None = None,
    ) -> None:
        self.entries: dict[str, HistoryEntry] = entries or {}

    # -- loading / saving -------------------------------------------------

    @classmethod
    def load(cls, path: Path | None) -> "ReliabilityHistory":
        """Load history; missing files start empty, corrupt files fail closed."""
        raw = load_json_state(path)
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise ValueError("history state has invalid schema")
        entries_raw = raw.get("entries", {})
        if not isinstance(entries_raw, dict):
            raise ValueError("history entries must be a mapping")
        entries: dict[str, HistoryEntry] = {}
        for fingerprint, item in entries_raw.items():
            if not isinstance(item, dict):
                continue
            try:
                cores_raw = item.get("cores") or {}
                cores = {
                    str(core): {
                        "checks": int(bucket.get("checks", 0)),
                        "passed": int(bucket.get("passed", 0)),
                    }
                    for core, bucket in cores_raw.items()
                    if isinstance(bucket, dict)
                } if isinstance(cores_raw, dict) else {}
                entry = HistoryEntry(
                    fingerprint=str(item.get("fingerprint") or fingerprint),
                    checks_total=int(item.get("checks_total") or 0),
                    checks_passed=int(item.get("checks_passed") or 0),
                    consecutive_successes=int(item.get("consecutive_successes") or 0),
                    consecutive_failures=int(item.get("consecutive_failures") or 0),
                    last_success=item.get("last_success"),
                    last_failure=item.get("last_failure"),
                    last_latency_ms=item.get("last_latency_ms"),
                    rolling_success_rate=float(item.get("rolling_success_rate") or 0.0),
                    recent=[int(v) for v in item.get("recent", [])][:MAX_RECENT],
                    last_seen=item.get("last_seen"),
                    first_discovered=item.get("first_discovered"),
                    last_discovered=item.get("last_discovered"),
                    preflight_scheduled_total=int(item.get("preflight_scheduled_total") or 0),
                    runtime_scheduled_total=int(item.get("runtime_scheduled_total") or 0),
                    last_preflight_scheduled=item.get("last_preflight_scheduled"),
                    last_runtime_scheduled=item.get("last_runtime_scheduled"),
                    cores=cores,
                )
            except (TypeError, ValueError) as exc:
                logger.warning("skipping corrupt history entry: %s", exc)
                continue
            entries[fingerprint] = entry
        # Stage 3 moved source intelligence to data/discovery.json.
        # Older history files may still contain a top-level "sources" object;
        # it is intentionally ignored during migration.
        return cls(entries)

    def save(self, path: Path | None) -> None:
        """Atomically persist the history (no-op when ``path`` is None)."""
        if path is None:
            return
        payload = {
            "schema_version": SCHEMA_VERSION,
            "entries": {fp: asdict(entry) for fp, entry in sorted(self.entries.items())},
        }
        atomic_write_json(path, payload)

    # -- recording --------------------------------------------------------

    def get(self, fingerprint: str) -> HistoryEntry | None:
        return self.entries.get(fingerprint)

    def observe_candidate(
        self, fingerprint: str, *, timestamp: str | None = None
    ) -> HistoryEntry:
        """Record that a credential-free fingerprint was discovered this run.

        Observation is intentionally distinct from verification: merely seeing a
        candidate must not improve or damage reliability. Persisting discovery
        timestamps lets the Stage 6 scheduler rotate never-tested nodes instead
        of selecting the same deterministic prefix forever.
        """
        entry = self.entries.get(fingerprint)
        if entry is None:
            entry = HistoryEntry(fingerprint=fingerprint)
            self.entries[fingerprint] = entry
        ts = timestamp or _utc_now_iso()
        if entry.first_discovered is None:
            entry.first_discovered = ts
        entry.last_discovered = ts
        return entry

    def mark_scheduled(
        self,
        fingerprint: str,
        *,
        phase: str,
        timestamp: str | None = None,
    ) -> HistoryEntry:
        """Persist one scheduler selection without changing reliability.

        ``phase`` is either ``preflight`` or ``runtime``. Keeping the two
        counters separate means a node that repeatedly survives cheap preflight
        but misses the runtime budget will be promoted on the next run.
        """
        entry = self.observe_candidate(fingerprint, timestamp=timestamp)
        ts = timestamp or _utc_now_iso()
        if phase == "preflight":
            entry.preflight_scheduled_total += 1
            entry.last_preflight_scheduled = ts
        elif phase == "runtime":
            entry.runtime_scheduled_total += 1
            entry.last_runtime_scheduled = ts
        else:
            raise ValueError(f"unknown scheduling phase: {phase}")
        return entry

    # -- per-core records (multi-core layer) --------------------------------

    def record_core(self, fingerprint: str, core: str, *, passed: bool) -> None:
        """Record one per-core outcome for a node fingerprint."""
        entry = self.entries.get(fingerprint)
        if entry is None:
            entry = HistoryEntry(fingerprint=fingerprint)
            self.entries[fingerprint] = entry
        entry.record_core(core, passed=passed)

    # -- pruning (Task 3: bounded growth) -----------------------------------

    def _effective_last_seen(self, entry: HistoryEntry) -> datetime | None:
        """Best-known activity timestamp for pruning decisions.

        Preference order: verification activity, discovery, then scheduling.
        Entries with no timestamps at all have never been recorded and are
        prunable; entries with timestamps that fail to parse are kept
        (defensive: never discard data because of a corrupt string).
        """
        for value in (
            entry.last_seen,
            entry.last_success,
            entry.last_failure,
            entry.last_discovered,
            entry.last_runtime_scheduled,
            entry.last_preflight_scheduled,
            entry.first_discovered,
        ):
            if value:
                try:
                    return datetime.fromisoformat(str(value))
                except ValueError:
                    continue
        return None

    def prune(
        self,
        *,
        retention_days: int,
        max_entries: int,
        now: datetime | None = None,
    ) -> tuple[int, int]:
        """Drop stale and excess entries so the file stays bounded.

        Two independent policies (both configurable, see
        ``config/testing.yaml`` -> ``history``):

        1. ``retention_days``: entries whose last known activity is older
           than this many days are removed.
        2. ``max_entries``: hard cap; when exceeded, the *least recently*
           active entries are removed first. Ties are broken by fingerprint
           so the result is deterministic.

        Entries without any parseable timestamp are treated as stale.
        Returns ``(pruned_stale, pruned_excess)``.
        """
        now = now or datetime.now(timezone.utc)
        pruned_stale = 0
        if retention_days > 0:
            cutoff = now - timedelta(days=retention_days)
            for fingerprint in sorted(self.entries):
                entry = self.entries[fingerprint]
                seen = self._effective_last_seen(entry)
                if seen is None or seen < cutoff:
                    del self.entries[fingerprint]
                    pruned_stale += 1
        pruned_excess = 0
        if max_entries > 0 and len(self.entries) > max_entries:
            oldest_first = sorted(
                self.entries.items(),
                key=lambda item: (
                    0 if self._effective_last_seen(item[1]) is None else 1,
                    self._effective_last_seen(item[1]) or datetime.min.replace(tzinfo=timezone.utc),
                    item[0],
                ),
            )
            excess = len(self.entries) - max_entries
            for fingerprint, _entry in oldest_first[:excess]:
                del self.entries[fingerprint]
                pruned_excess += 1
        return pruned_stale, pruned_excess

    def record(
        self,
        fingerprint: str,
        *,
        passed: bool,
        latency_ms: float | None = None,
        timestamp: str | None = None,
    ) -> HistoryEntry:
        """Record one check outcome and return the updated entry."""
        entry = self.observe_candidate(fingerprint, timestamp=timestamp)

        ts = timestamp or _utc_now_iso()
        entry.last_seen = ts
        entry.checks_total += 1
        if passed:
            entry.checks_passed += 1
            entry.consecutive_successes += 1
            entry.consecutive_failures = 0
            entry.last_success = ts
        else:
            entry.consecutive_failures += 1
            entry.consecutive_successes = 0
            entry.last_failure = ts
        if latency_ms is not None and passed:
            entry.last_latency_ms = float(latency_ms)
        entry.recent.append(1 if passed else 0)
        if len(entry.recent) > MAX_RECENT:
            del entry.recent[: len(entry.recent) - MAX_RECENT]
        entry.recompute_rolling()
        return entry
