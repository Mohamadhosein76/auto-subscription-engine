"""Bounded DNS resolution primitives used by the static-IP hunter and security.

Resolution is deliberately provider-pluggable.  The default production stack
uses the runner/system resolver plus one independent DNS-over-HTTPS JSON
resolver.  Operator-specific DNS resolvers can be injected by later probe
stages without changing the hunter.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import time
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote

import requests

from .address import canonicalize_host, is_public_ip


@dataclass(frozen=True)
class ResolverAnswer:
    resolver: str
    addresses: tuple[str, ...] = ()
    elapsed_ms: float | None = None
    error: str | None = None

    @property
    def public_addresses(self) -> tuple[str, ...]:
        return tuple(address for address in self.addresses if is_public_ip(address))


class Resolver(Protocol):
    name: str

    def resolve(self, host: str) -> ResolverAnswer: ...


class SystemResolver:
    name = "system"

    def resolve(self, host: str) -> ResolverAnswer:
        started = time.perf_counter()
        try:
            addresses = tuple(system_resolve(host))
        except Exception as exc:  # pragma: no cover - defensive adapter boundary
            return ResolverAnswer(
                resolver=self.name,
                elapsed_ms=(time.perf_counter() - started) * 1000.0,
                error=type(exc).__name__,
            )
        return ResolverAnswer(
            resolver=self.name,
            addresses=addresses,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )


class JsonDohResolver:
    def __init__(
        self,
        *,
        name: str,
        url: str,
        timeout: float = 5.0,
        session: requests.Session | None = None,
    ) -> None:
        self.name = str(name).strip() or "doh"
        self.url = str(url).strip()
        self.timeout = max(0.1, float(timeout))
        self._session = session

    def resolve(self, host: str) -> ResolverAnswer:
        started = time.perf_counter()
        addresses = doh_json_resolve(
            host,
            doh_url=self.url,
            timeout=self.timeout,
            session=self._session,
        )
        elapsed = (time.perf_counter() - started) * 1000.0
        if addresses is None:
            return ResolverAnswer(
                resolver=self.name,
                elapsed_ms=elapsed,
                error="provider_unavailable",
            )
        return ResolverAnswer(
            resolver=self.name,
            addresses=tuple(addresses),
            elapsed_ms=elapsed,
        )


def system_resolve(host: str) -> list[str]:
    """Resolve a hostname via the system resolver, returning A and AAAA."""
    found: set[str] = set()
    try:
        infos = socket.getaddrinfo(
            canonicalize_host(host),
            None,
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, OSError):
        return []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr or not sockaddr[0]:
            continue
        try:
            found.add(str(ipaddress.ip_address(str(sockaddr[0]).strip())))
        except ValueError:
            continue
    return sorted(found, key=_ip_sort_key)


def doh_json_resolve(
    host: str,
    *,
    doh_url: str,
    timeout: float,
    session: requests.Session | None = None,
) -> list[str] | None:
    """Resolve A/AAAA records through a DNS JSON endpoint.

    ``None`` means the provider itself was unavailable.  An empty list means
    the provider answered successfully but returned no usable address records.
    """
    found: set[str] = set()
    close = False
    if session is None:
        session = requests.Session()
        close = True
    try:
        for record_type in (1, 28):
            try:
                response = session.get(
                    doh_url,
                    params={
                        "name": quote(canonicalize_host(host), safe="."),
                        "type": record_type,
                    },
                    timeout=float(timeout),
                )
                response.raise_for_status()
                payload = response.json()
            except (requests.RequestException, ValueError, json.JSONDecodeError):
                return None
            answers = payload.get("Answer") if isinstance(payload, dict) else None
            if not isinstance(answers, list):
                continue
            for answer in answers:
                if not isinstance(answer, dict) or answer.get("type") not in (1, 28):
                    continue
                data = answer.get("data")
                if not isinstance(data, str):
                    continue
                try:
                    found.add(str(ipaddress.ip_address(data.strip())))
                except ValueError:
                    continue
        return sorted(found, key=_ip_sort_key)
    finally:
        if close:
            session.close()


def _ip_sort_key(value: str) -> tuple[int, int]:
    ip = ipaddress.ip_address(value)
    return (ip.version, int(ip))
