"""Persistent, bounded, verified cache for security intelligence feeds.

Location: ``data/security/feeds/<source>.json`` (committed to ``main``
by the workflow, exactly like ``data/history.json``). Committing the
cache is what keeps the *hourly* workflow from re-downloading feeds:
each feed is refreshed at most once per 24 hours by policy.

Record format (deterministic JSON, sorted keys, fixed indent):

.. code-block:: json

    {
      "schema_version": 1,
      "source": "spamhaus_drop",
      "url": "https://www.spamhaus.org/drop/drop.txt",
      "fetched_at": "2026-09-29T11:00:00+00:00",
      "expires_at": "2026-10-03T11:00:00+00:00",
      "source_version": "2026-09-29",
      "attribution": "Spamhaus DROP (c) The Spamhaus Project...",
      "content_hash": "sha256 hex of the raw downloaded payload",
      "entries_hash": "sha256 hex of the normalized entries JSON",
      "entry_count": 1320,
      "entries": ["1.2.3.0/24", "..."]
    }

Guarantees:

- **atomic write** — temp file + ``os.replace``, a crash never truncates;
- **corruption recovery** — an unreadable/invalid file is reported as a
  cache miss (never crashes the pipeline) and refreshed;
- **verification** — ``entries_hash`` is recomputed on load and compared;
  a mismatch is treated as corruption;
- **bounded** — a hard cap on stored entries (oldest-first truncation is
  *not* needed for reputation feeds, which are small; the cap is a
  backstop against a malformed/hostile feed body);
- **no secrets** — feed entries are public network/ASN data only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
#: Backstop cap on entries per feed (real feeds stay far below this).
MAX_ENTRIES_PER_FEED = 200_000


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def entries_digest(entries: list) -> str:
    """Stable hash over the normalized entry list (verification on load)."""
    payload = json.dumps(sorted(entries), separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class FeedRecord:
    """One cached feed (metadata + normalized entries)."""

    source: str
    url: str
    fetched_at: datetime
    expires_at: datetime
    entries: list = field(default_factory=list)
    source_version: str | None = None
    attribution: str | None = None
    content_hash: str | None = None

    def age_hours(self, now: datetime | None = None) -> float:
        now = now or utc_now()
        return max(0.0, (now - self.fetched_at).total_seconds()) / 3600.0

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "source": self.source,
            "url": self.url,
            "fetched_at": _iso(self.fetched_at),
            "expires_at": _iso(self.expires_at),
            "source_version": self.source_version,
            "attribution": self.attribution,
            "content_hash": self.content_hash,
            "entries_hash": entries_digest(self.entries),
            "entry_count": len(self.entries),
            "entries": self.entries,
        }


class FeedCache:
    """File-backed store of :class:`FeedRecord` objects."""

    def __init__(self, cache_dir: Path) -> None:
        # No mkdir here: a read-only/absent location must stay a cache
        # miss, not a crash. Directories are created lazily on save.
        self.cache_dir = Path(cache_dir)

    def path_for(self, source: str) -> Path:
        return self.cache_dir / f"{source}.json"

    def load(self, source: str) -> FeedRecord | None:
        """Load a feed record; ``None`` on absence/corruption/hash mismatch."""
        path = self.path_for(source)
        if not path.is_file():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
            logger.warning("security feed cache %s unreadable (%s) - will refresh", source, type(exc).__name__)
            return None
        if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
            logger.warning("security feed cache %s has an unsupported format - will refresh", source)
            return None
        entries = raw.get("entries")
        fetched = raw.get("fetched_at")
        expires = raw.get("expires_at")
        if not isinstance(entries, list) or not fetched or not expires:
            logger.warning("security feed cache %s is incomplete - will refresh", source)
            return None
        if raw.get("entry_count") != len(entries):
            logger.warning("security feed cache %s entry count mismatch - will refresh", source)
            return None
        if entries_digest(entries) != raw.get("entries_hash"):
            logger.warning("security feed cache %s failed hash verification - will refresh", source)
            return None
        try:
            record = FeedRecord(
                source=str(raw.get("source") or source),
                url=str(raw.get("url") or ""),
                fetched_at=datetime.fromisoformat(fetched),
                expires_at=datetime.fromisoformat(expires),
                entries=entries,
                source_version=raw.get("source_version"),
                attribution=raw.get("attribution"),
                content_hash=raw.get("content_hash"),
            )
        except ValueError:
            logger.warning("security feed cache %s has invalid timestamps - will refresh", source)
            return None
        return record

    def save(self, record: FeedRecord) -> None:
        """Atomically persist a record (temp file + rename, deterministic)."""
        record.entries = list(record.entries)[:MAX_ENTRIES_PER_FEED]
        payload = json.dumps(record.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        path = self.path_for(record.source)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(self.cache_dir), prefix=f".{record.source}-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o644)
            os.replace(tmp_name, path)
        except OSError:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    # -- freshness helpers ---------------------------------------------------

    @staticmethod
    def is_fresh(record: FeedRecord | None, refresh_interval_hours: float,
                 now: datetime | None = None) -> bool:
        """True when the cache may be reused without a re-download."""
        if record is None:
            return False
        now = now or utc_now()
        return record.age_hours(now) < float(refresh_interval_hours)

    @staticmethod
    def is_usable(record: FeedRecord | None, max_age_hours: float,
                  now: datetime | None = None) -> bool:
        """True when the cache is stale-but-tolerable (feed fetch failed)."""
        if record is None:
            return False
        now = now or utc_now()
        return record.age_hours(now) <= float(max_age_hours)


def build_record(
    source: str,
    url: str,
    entries: list,
    raw_content: bytes,
    refresh_interval_hours: float,
    max_age_hours: float,
    *,
    now: datetime | None = None,
    source_version: str | None = None,
    attribution: str | None = None,
) -> FeedRecord:
    """Create a cache record from a freshly downloaded feed payload."""
    from .feeds import _attribution_for

    now = now or utc_now()
    return FeedRecord(
        source=source,
        url=url,
        fetched_at=now,
        expires_at=now + timedelta(hours=float(max_age_hours)),
        entries=entries,
        source_version=source_version,
        attribution=attribution or _attribution_for(source),
        content_hash=hashlib.sha256(raw_content).hexdigest(),
    )
