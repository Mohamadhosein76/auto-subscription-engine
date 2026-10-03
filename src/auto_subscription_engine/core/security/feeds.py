"""Reputation feed fetching, parsing and refresh policy (Task 4).

Supported feeds (all official, free, key-free):

- **Spamhaus DROP** (IPv4 hijacked/hijacked-announced netblocks)
- **Spamhaus DROPv6** (IPv6 equivalents)
- **Spamhaus ASN-DROP** (autonomous systems controlled by spammers/
  malware operations — judged by official evidence, never by hosting type)
- **Feodo Tracker recommended blocklist** — *currently active* botnet C2
  hosts only. The aggressive/historical Feodo lists are deliberately NOT
  consumed (documented false-positive tradeoff).

Refresh policy (rate guard): a feed is downloaded at most once per
``refresh_interval_hours`` (default 24h) — the persisted cache in
``data/security/feeds/`` serves everything in between. If a download
fails and the cache is still usable (within ``max_age_hours``) the cache
is used. If a *required* feed can neither be downloaded nor served from
a non-stale cache, :class:`FeedUnavailableError` is raised: the security
stage then halts the run and the previous healthy subscription is kept.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import requests

from ..version import HTTP_USER_AGENT

from .feedcache import FeedCache, FeedRecord, build_record, utc_now

logger = logging.getLogger(__name__)

#: Feed ids (also the cache file names under data/security/feeds/).
SOURCE_SPAMHAUS_DROP = "spamhaus_drop"
SOURCE_SPAMHAUS_DROPV6 = "spamhaus_dropv6"
SOURCE_SPAMHAUS_ASNDROP = "spamhaus_asndrop"
SOURCE_FEODO_RECOMMENDED = "feodo_recommended"

REQUIRED_SOURCES = (
    SOURCE_SPAMHAUS_DROP,
    SOURCE_SPAMHAUS_DROPV6,
    SOURCE_SPAMHAUS_ASNDROP,
    SOURCE_FEODO_RECOMMENDED,
)

#: Bounded retry backoff between feed download attempts (seconds).
_RETRY_BACKOFF_SECONDS = 1.0

SPAMHAUS_ATTRIBUTION = (
    "Spamhaus DROP/DROPv6/ASN-DROP data (c) The Spamhaus Project Ltd. "
    "https://www.spamhaus.org/drop/ - used in accordance with the "
    "Spamhaus data usage policy (attribution retained)."
)
FEODO_ATTRIBUTION = (
    "Feodo Tracker recommended IP blocklist (c) abuse.ch "
    "https://feodotracker.abuse.ch/ - free for any use; currently active "
    "botnet C2 infrastructure only."
)


class FeedUnavailableError(Exception):
    """A required security feed is neither fresh nor refreshable."""


@dataclass
class FeedView:
    """Parsed, ready-to-query view over all required feeds."""

    drop_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    asndrop_asns: set[int]
    feodo_ips: set[str]
    records: dict[str, FeedRecord]
    statuses: dict[str, str]  # source -> "fresh" | "cached" | "downloaded"


def fetch_text(
    url: str,
    *,
    timeout: float,
    retries: int,
    max_bytes: int,
    session: requests.Session | None = None,
) -> bytes:
    """Download a feed body with bounded retries and a hard size cap."""
    close = False
    if session is None:
        session = requests.Session()
        close = True
    # A descriptive, honest User-Agent: many feed providers (including
    # Spamhaus) rate-limit or block anonymous default client agents.
    session.headers.setdefault("User-Agent", HTTP_USER_AGENT)
    try:
        last_error: Exception | None = None
        for attempt in range(max(1, int(retries) + 1)):
            if attempt:
                time.sleep(_RETRY_BACKOFF_SECONDS * attempt)
            try:
                response = session.get(url, timeout=float(timeout), stream=True)
                response.raise_for_status()
                chunks: list[bytes] = []
                received = 0
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    received += len(chunk)
                    if received > int(max_bytes):
                        raise ValueError(f"feed payload exceeds {max_bytes} bytes")
                    chunks.append(chunk)
                return b"".join(chunks)
            except (requests.RequestException, ValueError) as exc:
                last_error = exc
                logger.debug("feed fetch attempt %d failed for %s", attempt + 1, type(exc).__name__)
        assert last_error is not None
        raise ConnectionError(f"feed download failed after retries: {type(last_error).__name__}")
    finally:
        if close:
            session.close()


def parse_spamhaus_drop(text: str) -> list[str]:
    """Normalize a Spamhaus DROP/DROPv6 body into CIDR strings.

    Lines look like ``1.2.3.0/24 ; S1234`` with ``#`` comments. Invalid
    lines are skipped (a malformed advisory entry must not crash a run).
    """
    networks: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(";", 1)[0].strip()
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            logger.debug("skipping malformed DROP line: %s", token[:32])
            continue
        networks.append(str(network))
    # deterministic, de-duplicated
    return sorted(set(networks))


def parse_spamhaus_asndrop(text: str) -> list[int]:
    """Normalize an ASN-DROP body into a sorted set of AS integers.

    Two upstream formats are supported:
    - the retired legacy text (``AS12345 ; S0000`` / ``AS12345 | name``),
    - the current **JSON Lines** flavour (``{"asn": 123, ...}`` per line,
      terminated by a ``{"type": "metadata", ...}`` record).
    """
    asns: set[int] = set()
    stripped = text.lstrip()
    if stripped.startswith("{"):
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict) or record.get("type") == "metadata":
                continue
            raw = record.get("asn")
            if isinstance(raw, int):
                asns.add(raw)
            elif isinstance(raw, str) and raw.strip().isdigit():
                asns.add(int(raw.strip()))
        return sorted(asns)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        token = line.split(";", 1)[0].split("|", 1)[0].strip().upper()
        if not token:
            continue
        if token.startswith("AS") and token[2:].isdigit():
            asns.add(int(token[2:]))
    return sorted(asns)


def asndrop_metadata(text: str) -> dict:
    """Extract the trailing metadata record from the ASN-DROP JSON feed."""
    if not text.lstrip().startswith("{"):
        return {}
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and record.get("type") == "metadata":
            return record
    return {}


def parse_feodo_recommended(text: str) -> list[str]:
    """Normalize the Feodo recommended blocklist into IP strings.

    The official JSON flavor is a list of objects with ``ip_address``;
    the plain-text flavor is one IP per line with ``#`` comments. Both
    are accepted so an upstream format change degrades gracefully.
    """
    ips: set[str] = set()
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("feodo recommended JSON unreadable - treating as empty")
            return []
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    candidate = item.get("ip_address") or item.get("ip")
                    _add_ip(ips, candidate)
        return sorted(ips)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        _add_ip(ips, line)
    return sorted(ips)


def _add_ip(bucket: set[str], candidate: object) -> None:
    if not isinstance(candidate, str) or not candidate.strip():
        return
    try:
        bucket.add(str(ipaddress.ip_address(candidate.strip())))
    except ValueError:
        logger.debug("skipping malformed feed IP: %.32s", candidate)


def _source_version_from_text(text: str) -> str | None:
    """Best-effort advisory date from feed comments or JSON metadata."""
    meta = asndrop_metadata(text)
    if meta.get("timestamp"):
        return str(meta["timestamp"])
    for line in text.splitlines():
        if line.startswith(("#", ";")):
            lowered = line.lower()
            if "as of" in lowered or "data as of" in lowered:
                token = line.split(":", 1)[-1].strip() if ":" in line else line
                return token.lstrip("#; ").strip()[:64] or None
    return None


def _parse_entries(source: str, raw: bytes) -> tuple[list, str | None]:
    text = raw.decode("utf-8", errors="replace")
    if source in (SOURCE_SPAMHAUS_DROP, SOURCE_SPAMHAUS_DROPV6):
        return parse_spamhaus_drop(text), _source_version_from_text(text)
    if source == SOURCE_SPAMHAUS_ASNDROP:
        return parse_spamhaus_asndrop(text), _source_version_from_text(text)
    if source == SOURCE_FEODO_RECOMMENDED:
        return parse_feodo_recommended(text), None
    raise ValueError(f"unknown feed source: {source}")


def _attribution_for(source: str) -> str:
    if source.startswith("spamhaus"):
        return SPAMHAUS_ATTRIBUTION
    if source.startswith("feodo"):
        return FEODO_ATTRIBUTION
    return "public reputation feed"


def refresh_feeds(
    feed_cfg: dict,
    cache: FeedCache,
    *,
    now: datetime | None = None,
    session: requests.Session | None = None,
    downloader=None,
) -> tuple[dict[str, FeedRecord], dict[str, str]]:
    """Refresh every required feed honoring the rate/staleness policy.

    Returns ``(records, statuses)`` where status is one of
    ``fresh`` (cache reused, still young), ``cached`` (download failed,
    stale-but-usable cache served), or ``downloaded``.

    Raises :class:`FeedUnavailableError` when a required feed is neither
    downloadable nor cached within ``max_age_hours`` — callers must halt
    publishing in that case (never publish unchecked nodes).
    """
    now = now or utc_now()
    refresh_interval = float(feed_cfg.get("refresh_interval_hours", 24))
    max_age = float(feed_cfg.get("max_age_hours", 96))
    timeout = float(feed_cfg.get("timeout_seconds", 20.0))
    retries = int(feed_cfg.get("retries", 2))
    max_bytes = int(feed_cfg.get("max_bytes", 5 * 1024 * 1024))

    records: dict[str, FeedRecord] = {}
    statuses: dict[str, str] = {}

    url_by_source = {
        SOURCE_SPAMHAUS_DROP: feed_cfg.get("spamhaus_drop"),
        SOURCE_SPAMHAUS_DROPV6: feed_cfg.get("spamhaus_dropv6"),
        SOURCE_SPAMHAUS_ASNDROP: feed_cfg.get("spamhaus_asndrop"),
        SOURCE_FEODO_RECOMMENDED: feed_cfg.get("feodo_recommended"),
    }

    for source in REQUIRED_SOURCES:
        url = url_by_source.get(source)
        if not url:
            raise FeedUnavailableError(f"no URL configured for required feed {source}")
        cached = cache.load(source)
        if FeedCache.is_fresh(cached, refresh_interval, now):
            records[source] = cached
            statuses[source] = "fresh"
            continue
        try:
            if downloader is not None:
                raw = downloader(url)
            else:
                raw = fetch_text(
                    url, timeout=timeout, retries=retries, max_bytes=max_bytes, session=session
                )
            entries, source_version = _parse_entries(source, raw)
            if not entries:
                # An empty payload from a required feed is anomalous (a
                # retired URL often answers 200 with a notice page).
                # Refuse it: fall back to the cache or halt the run -
                # never silently disable a protection layer.
                raise ValueError(f"feed {source} returned zero entries")
            record = build_record(
                source,
                str(url),
                entries,
                raw,
                refresh_interval,
                max_age,
                now=now,
                source_version=source_version,
                attribution=_attribution_for(source),
            )
            cache.save(record)
            records[source] = record
            statuses[source] = "downloaded"
        except (ConnectionError, ValueError, OSError, json.JSONDecodeError) as exc:
            if FeedCache.is_usable(cached, max_age, now):
                records[source] = cached
                statuses[source] = "cached"
                logger.warning(
                    "feed %s refresh failed (%s) - serving stale-but-valid cache "
                    "fetched %s",
                    source,
                    type(exc).__name__,
                    cached.fetched_at.isoformat(),
                )
            else:
                raise FeedUnavailableError(
                    f"required feed {source} is unavailable and its cache is "
                    f"stale beyond max_age_hours={max_age:g}"
                ) from exc

    return records, statuses


def build_feed_view(records: dict[str, FeedRecord]) -> FeedView:
    """Compile cached feed records into the query structures the policy uses."""
    drop_networks: list = []
    for source in (SOURCE_SPAMHAUS_DROP, SOURCE_SPAMHAUS_DROPV6):
        for cidr in records.get(source).entries if records.get(source) else []:
            try:
                drop_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
    asndrop = records.get(SOURCE_SPAMHAUS_ASNDROP)
    asns = {int(a) for a in (asndrop.entries if asndrop else []) if str(a).isdigit()}
    feodo = records.get(SOURCE_FEODO_RECOMMENDED)
    feodo_ips = {str(ip) for ip in (feodo.entries if feodo else [])}
    return FeedView(
        drop_networks=drop_networks,
        asndrop_asns=asns,
        feodo_ips=feodo_ips,
        records=records,
        statuses={},
    )


def ip_in_drop_networks(ip: str, networks: list) -> bool:
    """Membership test for a resolved endpoint IP against DROP networks."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in networks)


def default_cache_dir(data_dir: Path | None = None) -> Path:
    """``data/security/feeds`` next to the project's data directory."""
    base = Path(data_dir) if data_dir else Path("data")
    return base / "security" / "feeds"
