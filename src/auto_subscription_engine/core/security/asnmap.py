"""ASN intelligence: map resolved endpoint IPs to autonomous systems.

Primary source: **Team Cymru IP-to-ASN** bulk whois (``whois.cymru.com``
port 43, one ``begin/verbose/end`` batch for *all* IPs in the run — one
connection, polite by design). Fallback per-IP: **RIPEstat network-info**
(key-free HTTPS API).

The mapping is *enrichment*: an ASN alone never blocks a node. Only the
official Spamhaus ASN-DROP feed turns an ASN into a hard block. Hosting/
datacenter ASNs (AWS, Google, OVH, Hetzner, ...) are ordinary metadata —
most healthy proxies naturally live there.

A persistent per-IP cache (``data/security/asn_cache.json``, committed)
prevents repeated lookups for the same IP across runs; entries expire
after ``cache_ttl_hours`` and the file is pruned to ``max_cache_entries``
(least-recently-looked-up first). Writes are atomic; corruption restarts
the cache instead of crashing the run.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
_SOURCE_CYMRU = "cymru_whois"
_SOURCE_RIPESTAT = "ripestat"
_SOURCE_CACHE = "cache"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


@dataclass
class AsnInfo:
    """ASN metadata for one resolved endpoint IP (credential-free)."""

    asn: int | None = None
    as_name: str | None = None
    prefix: str | None = None
    source: str | None = None
    looked_up_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "asn": self.asn,
            "as_name": self.as_name,
            "prefix": self.prefix,
            "source": self.source,
            "looked_up_at": self.looked_up_at,
        }


# ---------------------------------------------------------------------------
# Persistent per-IP cache
# ---------------------------------------------------------------------------


class AsnCache:
    """Bounded, atomic, corruption-tolerant IP -> ASN cache."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, dict]:
        if not self.path.is_file():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
            logger.warning("ASN cache unreadable (%s) - starting empty", type(exc).__name__)
            return {}
        if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
            logger.warning("ASN cache format unsupported - starting empty")
            return {}
        entries = raw.get("entries")
        if not isinstance(entries, dict):
            return {}
        return entries

    def save(self, entries: dict[str, dict]) -> None:
        payload = json.dumps(
            {"schema_version": SCHEMA_VERSION, "entries": entries},
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(self.path.parent), prefix=".asn-cache-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o644)
            os.replace(tmp_name, self.path)
        except OSError:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    @staticmethod
    def prune(entries: dict[str, dict], ttl_hours: float, max_entries: int,
              now: datetime | None = None) -> dict[str, dict]:
        """Drop expired entries, then hard-cap by least-recent lookups."""
        now = now or datetime.now(timezone.utc)
        deadline = now - timedelta(hours=float(ttl_hours))
        kept: dict[str, dict] = {}
        for ip, item in entries.items():
            if not isinstance(item, dict):
                continue
            stamp = item.get("looked_up_at")
            try:
                looked_up = datetime.fromisoformat(str(stamp))
            except (TypeError, ValueError):
                continue  # undated entries cannot be trusted - drop
            if looked_up < deadline:
                continue
            kept[ip] = item
        if len(kept) > int(max_entries):
            ordered = sorted(
                kept.items(),
                key=lambda kv: kv[1].get("looked_up_at") or "",
                reverse=True,
            )
            kept = dict(ordered[: int(max_entries)])
        return kept


# ---------------------------------------------------------------------------
# Team Cymru bulk whois (primary)
# ---------------------------------------------------------------------------


def cymru_bulk_lookup(
    ips: list[str],
    *,
    host: str,
    port: int,
    timeout: float,
) -> dict[str, AsnInfo]:
    """One bulk whois query for many IPs; returns parsed mappings.

    Wire format (verbose bulk): a header line, a column header line, then
    rows ``AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name``.
    Unresolvable IPs come back as ``NA`` fields and map to ``AsnInfo()``.
    Any transport error raises :class:`OSError` so callers can fall back.
    """
    if not ips:
        return {}
    payload = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    with socket.create_connection((host, int(port)), timeout=float(timeout)) as sock:
        sock.settimeout(float(timeout))
        sock.sendall(payload.encode("ascii"))
        buffer = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
            if len(buffer) > 4 * 1024 * 1024:
                raise ValueError("cymru bulk response too large")
    return _parse_cymru_response(buffer.decode("utf-8", errors="replace"))


def _parse_cymru_response(text: str) -> dict[str, AsnInfo]:
    results: dict[str, AsnInfo] = {}
    now = _iso(datetime.now(timezone.utc))
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("bulk mode"):
            continue
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        asn_text, ip_text, prefix, _cc, _registry, _allocated, as_name = parts[:7]
        if not ip_text or ip_text.upper() == "NA":
            continue
        info = AsnInfo(source=_SOURCE_CYMRU, looked_up_at=now)
        if asn_text and asn_text.upper() != "NA":
            try:
                info.asn = int(asn_text)
            except ValueError:
                info.asn = None
        if prefix and prefix.upper() != "NA":
            info.prefix = prefix
        if as_name and as_name.upper() != "NA":
            info.as_name = as_name
        try:
            canonical = str(ipaddress.ip_address(ip_text))
        except ValueError:
            continue
        results[canonical] = info
    return results


# ---------------------------------------------------------------------------
# RIPEstat fallback (per-IP, bounded concurrency)
# ---------------------------------------------------------------------------


def ripestat_lookup(
    ip: str,
    *,
    url: str,
    timeout: float,
    session: requests.Session | None = None,
) -> AsnInfo:
    """One RIPEstat network-info lookup; returns an (possibly empty) AsnInfo.

    Current API answer shape: ``{"data": {"asns": ["15169"],
    "prefix": "8.8.8.0/24"}}``. Older deployments answered
    ``{"asn": "...", "holder": "...", "block": {...}}`` - both are parsed
    so an API roll-out cannot break the fallback mid-flight.
    """
    info = AsnInfo(source=_SOURCE_RIPESTAT, looked_up_at=_iso(datetime.now(timezone.utc)))
    close = False
    if session is None:
        session = requests.Session()
        close = True
    try:
        response = session.get(url, params={"resource": ip}, timeout=float(timeout))
        response.raise_for_status()
        data = (response.json() or {}).get("data") or {}
        if not isinstance(data, dict):
            return info
        # current shape: asns list
        asns = data.get("asns")
        if isinstance(asns, list) and asns:
            first = str(asns[0]).strip().split(",")[0].strip()
            if first.isdigit():
                info.asn = int(first)
        # legacy shape: singular asn
        if info.asn is None:
            asn_text = str(data.get("asn") or "").strip()
            if asn_text and asn_text.upper() != "NA":
                first = asn_text.split(",")[0].strip()
                if first.isdigit():
                    info.asn = int(first)
        holder = data.get("holder")
        if isinstance(holder, str) and holder.strip():
            info.as_name = holder.strip()[:200]
        # current shape: plain prefix; legacy: nested block.resource
        if isinstance(data.get("prefix"), str) and data["prefix"].strip():
            info.prefix = data["prefix"].strip()
        else:
            block = data.get("block")
            if isinstance(block, dict) and block.get("resource"):
                info.prefix = str(block["resource"])
        return info
    except (requests.RequestException, ValueError, json.JSONDecodeError):
        return info
    finally:
        if close:
            session.close()


# ---------------------------------------------------------------------------
# Orchestrated lookup with cache
# ---------------------------------------------------------------------------


def resolve_asn_map(
    ips: list[str],
    asn_cfg: dict,
    cache: AsnCache,
    *,
    now: datetime | None = None,
    session: requests.Session | None = None,
    whois_query=None,
) -> tuple[dict[str, AsnInfo], bool]:
    """Resolve ASN info for ``ips`` using cache -> cymru -> ripestat.

    Returns ``(mapping, complete)``. ``complete`` is False when at least
    one public IP could not be mapped by any source (the run continues —
    enrichment is optional — but the node metadata records the gap).
    """
    now = now or datetime.now(timezone.utc)
    ttl = float(asn_cfg.get("cache_ttl_hours", 336))
    max_entries = int(asn_cfg.get("max_cache_entries", 20000))
    max_lookups = int(asn_cfg.get("max_lookups_per_run", 5000))
    timeout = float(asn_cfg.get("timeout_seconds", 10.0))

    stored = AsnCache.prune(cache.load(), ttl, max_entries, now)

    wanted: list[str] = []
    for ip in dict.fromkeys(ips):
        try:
            address = ipaddress.ip_address(str(ip))
        except ValueError:
            continue
        if address.is_private or address.is_loopback or address.is_reserved \
                or address.is_link_local or address.is_multicast:
            continue  # non-routable endpoints have no public ASN
        wanted.append(str(address))
    wanted = wanted[:max_lookups]

    results: dict[str, AsnInfo] = {}
    pending: list[str] = []
    for ip in wanted:
        hit = stored.get(ip)
        if isinstance(hit, dict):
            results[ip] = AsnInfo(
                asn=hit.get("asn"),
                as_name=hit.get("as_name"),
                prefix=hit.get("prefix"),
                source=_SOURCE_CACHE,
                looked_up_at=hit.get("looked_up_at"),
            )
        else:
            pending.append(ip)

    if pending:
        fresh: dict[str, AsnInfo] = {}
        if whois_query is not None:
            fresh = dict(whois_query(pending))
        else:
            try:
                fresh = cymru_bulk_lookup(
                    pending,
                    host=str(asn_cfg.get("whois_host", "whois.cymru.com")),
                    port=int(asn_cfg.get("whois_port", 43)),
                    timeout=timeout,
                )
            except (OSError, ValueError) as exc:
                logger.warning("cymru bulk lookup failed (%s) - using RIPEstat fallback", type(exc).__name__)
        for ip in pending:
            if ip not in fresh:
                fresh[ip] = AsnInfo()  # marked incomplete below
        # RIPEstat fallback for anything cymru could not answer.
        unresolved = [ip for ip, info in fresh.items() if info.asn is None and info.source != _SOURCE_RIPESTAT]
        if unresolved:
            fallback_url = str(asn_cfg.get("fallback_url"))
            concurrency = max(1, int(asn_cfg.get("concurrency", 4)))
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = {
                    pool.submit(
                        ripestat_lookup,
                        ip,
                        url=fallback_url,
                        timeout=timeout,
                        session=session,
                    ): ip
                    for ip in unresolved
                }
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        info = future.result()
                    except Exception:  # defensive: enrichment must never kill the run
                        info = AsnInfo()
                    fresh[ip] = info
        for ip, info in fresh.items():
            results[ip] = info
            # Only cache *useful* mappings; a fully empty answer stays
            # uncached so the next run can retry it.
            if info.asn is not None or info.as_name or info.prefix:
                stored[ip] = info.to_dict()

    complete = all(results.get(ip).asn is not None for ip in wanted) if wanted else True
    try:
        cache.save(stored)
    except OSError as exc:
        logger.warning("cannot persist ASN cache: %s", type(exc).__name__)
    return results, complete
