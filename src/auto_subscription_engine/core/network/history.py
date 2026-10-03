"""Credential-free DNS history for static-IP candidate recovery."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..hardening.state import atomic_write_json, load_json_state

from .address import canonicalize_host, is_public_ip

_SCHEMA_VERSION = 1


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass
class AddressHistoryEntry:
    first_seen: str
    last_seen: str
    seen_count: int = 1
    resolvers: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, object]:
        return {
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "seen_count": int(self.seen_count),
            "resolvers": sorted(self.resolvers),
        }


@dataclass
class HostHistory:
    addresses: dict[str, AddressHistoryEntry] = field(default_factory=dict)


class DnsHistoryStore:
    """Small bounded JSON store keyed only by hostname and public address."""

    def __init__(self, path: Path | None, hosts: dict[str, HostHistory] | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self.hosts = hosts or {}

    @classmethod
    def load(cls, path: Path | None) -> "DnsHistoryStore":
        payload = load_json_state(path)
        if payload is None:
            return cls(path)
        raw_hosts = payload.get("hosts") if isinstance(payload, dict) else None
        if not isinstance(raw_hosts, dict):
            raise ValueError("DNS history state has invalid schema")
        hosts: dict[str, HostHistory] = {}
        for raw_host, raw_entry in raw_hosts.items():
            host = canonicalize_host(str(raw_host))
            if not host or not isinstance(raw_entry, dict):
                continue
            raw_addresses = raw_entry.get("addresses")
            if not isinstance(raw_addresses, dict):
                continue
            addresses: dict[str, AddressHistoryEntry] = {}
            for address, raw_address in raw_addresses.items():
                if not is_public_ip(str(address)) or not isinstance(raw_address, dict):
                    continue
                address = str(ipaddress.ip_address(str(address).strip()))
                first_seen = str(raw_address.get("first_seen") or "")
                last_seen = str(raw_address.get("last_seen") or "")
                if _parse_time(first_seen) is None or _parse_time(last_seen) is None:
                    continue
                addresses[str(address)] = AddressHistoryEntry(
                    first_seen=first_seen,
                    last_seen=last_seen,
                    seen_count=max(1, int(raw_address.get("seen_count") or 1)),
                    resolvers={
                        str(item)
                        for item in raw_address.get("resolvers", [])
                        if str(item).strip()
                    },
                )
            if addresses:
                hosts[host] = HostHistory(addresses=addresses)
        return cls(path, hosts)

    def observe(
        self,
        host: str,
        addresses_by_resolver: dict[str, list[str] | tuple[str, ...]],
        *,
        now: datetime | None = None,
    ) -> None:
        host = canonicalize_host(host)
        if not host:
            return
        now = (now or _utcnow()).astimezone(timezone.utc)
        stamp = now.isoformat(timespec="seconds")
        bucket = self.hosts.setdefault(host, HostHistory())
        observed: dict[str, set[str]] = {}
        for resolver, addresses in addresses_by_resolver.items():
            for address in addresses:
                address = str(address).strip()
                if is_public_ip(address):
                    address = str(ipaddress.ip_address(address))
                    observed.setdefault(address, set()).add(str(resolver))
        for address, resolvers in observed.items():
            entry = bucket.addresses.get(address)
            if entry is None:
                bucket.addresses[address] = AddressHistoryEntry(
                    first_seen=stamp,
                    last_seen=stamp,
                    seen_count=1,
                    resolvers=set(resolvers),
                )
            else:
                entry.last_seen = stamp
                entry.seen_count += 1
                entry.resolvers.update(resolvers)

    def recent_addresses(
        self,
        host: str,
        *,
        max_age_days: int,
        limit: int,
        now: datetime | None = None,
    ) -> list[str]:
        host = canonicalize_host(host)
        bucket = self.hosts.get(host)
        if bucket is None or limit <= 0:
            return []
        now = (now or _utcnow()).astimezone(timezone.utc)
        cutoff = now - timedelta(days=max(0, int(max_age_days)))
        ranked: list[tuple[datetime, int, str]] = []
        for address, entry in bucket.addresses.items():
            last_seen = _parse_time(entry.last_seen)
            if last_seen is None or last_seen < cutoff or not is_public_ip(address):
                continue
            ranked.append((last_seen, int(entry.seen_count), address))
        ranked.sort(key=lambda item: (-item[0].timestamp(), -item[1], item[2]))
        return [address for _last, _count, address in ranked[:limit]]

    def prune(
        self,
        *,
        retention_days: int,
        max_hosts: int,
        max_ips_per_host: int,
        now: datetime | None = None,
    ) -> None:
        now = (now or _utcnow()).astimezone(timezone.utc)
        cutoff = now - timedelta(days=max(1, int(retention_days)))
        host_last_seen: list[tuple[datetime, str]] = []
        for host in list(self.hosts):
            bucket = self.hosts[host]
            entries: list[tuple[datetime, int, str]] = []
            for address in list(bucket.addresses):
                entry = bucket.addresses[address]
                last_seen = _parse_time(entry.last_seen)
                if last_seen is None or last_seen < cutoff or not is_public_ip(address):
                    del bucket.addresses[address]
                    continue
                entries.append((last_seen, int(entry.seen_count), address))
            entries.sort(key=lambda item: (-item[0].timestamp(), -item[1], item[2]))
            for _last, _count, address in entries[max(1, int(max_ips_per_host)):]:
                bucket.addresses.pop(address, None)
            if not bucket.addresses:
                del self.hosts[host]
                continue
            newest = max(_parse_time(e.last_seen) or cutoff for e in bucket.addresses.values())
            host_last_seen.append((newest, host))
        host_last_seen.sort(key=lambda item: (-item[0].timestamp(), item[1]))
        for _last, host in host_last_seen[max(1, int(max_hosts)):]:
            self.hosts.pop(host, None)

    def save(self) -> None:
        if self.path is None:
            return
        payload = {
            "schema_version": _SCHEMA_VERSION,
            "hosts": {
                host: {
                    "addresses": {
                        address: entry.to_dict()
                        for address, entry in sorted(bucket.addresses.items())
                    }
                }
                for host, bucket in sorted(self.hosts.items())
            },
        }
        atomic_write_json(self.path, payload)
