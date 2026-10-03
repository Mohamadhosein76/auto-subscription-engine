"""Country detection based on the *server endpoint IP*.

Design (Task 2):

- the hostname is resolved by the TCP precheck; geolocation runs against
  that resolved endpoint IP — never against the GitHub runner IP and
  never against an exit-IP guess from an HTTP echo service;
- lookups use a key-free public service (ip-api.com) configured in
  ``config/testing.yaml`` so tests can point it at a local fake;
- results are cached per IP for the whole run and optionally rate
  limited in between requests;
- the batch endpoint is preferred (100 IPs per request) to stay well
  inside the provider's rate limit;
- any geolocation failure degrades to ``UNKNOWN`` and never fails the
  connectivity test of a node.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

import requests

from ..utils.redaction import redact_text
from ..version import HTTP_USER_AGENT

logger = logging.getLogger(__name__)

UNKNOWN_CODE = "UNKNOWN"
UNKNOWN_NAME = "Unknown"


@dataclass(frozen=True)
class GeoSettings:
    """Provider endpoints and limits (config/testing.yaml: ``geo``)."""

    batch_url: str = "http://ip-api.com/batch?fields=status,country,countryCode,query"
    single_url: str = (
        "http://ip-api.com/json/{ip}?fields=status,country,countryCode"
    )
    timeout_seconds: float = 5.0
    batch_size: int = 100
    batch_rate_per_minute: int = 15
    max_lookups: int = 1000


@dataclass(frozen=True)
class GeoInfo:
    """Geolocation outcome for one IP."""

    country_code: str = UNKNOWN_CODE
    country_name: str = UNKNOWN_NAME

    @property
    def known(self) -> bool:
        return self.country_code != UNKNOWN_CODE


@dataclass
class _RateLimiter:
    """Minimal interval-based rate limiter (one lock domain per resolver)."""

    min_interval_seconds: float
    _last: float = field(default=0.0)

    def wait(self) -> None:
        now = time.monotonic()
        delta = now - self._last
        remaining = self.min_interval_seconds - delta
        if remaining > 0:
            time.sleep(remaining)
        self._last = time.monotonic()


class GeoResolver:
    """Cached, rate-limited IP geolocation with graceful degradation."""

    def __init__(
        self,
        settings: GeoSettings = GeoSettings(),
        *,
        session: requests.Session | None = None,
    ) -> None:
        self.settings = settings
        self.session = session or requests.Session()
        self.cache: dict[str, GeoInfo] = {}
        self._limiter = _RateLimiter(60.0 / max(1, settings.batch_rate_per_minute))

    def lookup_many(self, ips: Iterable[str]) -> dict[str, GeoInfo]:
        """Resolve many IPs (batch endpoint, cache-first); never raises."""
        unique_ips: list[str] = []
        seen: set[str] = set()
        for ip in ips:
            if ip and ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)

        results: dict[str, GeoInfo] = {}
        pending: list[str] = []
        budget = self.settings.max_lookups
        for ip in unique_ips:
            cached = self.cache.get(ip)
            if cached is not None:
                results[ip] = cached
                continue
            if budget <= 0:
                results[ip] = GeoInfo()
                continue
            budget -= 1
            pending.append(ip)

        for start in range(0, len(pending), max(1, self.settings.batch_size)):
            chunk = pending[start : start + max(1, self.settings.batch_size)]
            chunk_results = self._lookup_batch(chunk)
            for ip, info in chunk_results.items():
                self.cache[ip] = info
                results[ip] = info
        return results

    def lookup_one(self, ip: str) -> GeoInfo:
        """Single-IP fallback lookup; UNKNOWN on any failure."""
        if not ip:
            return GeoInfo()
        cached = self.cache.get(ip)
        if cached is not None:
            return cached
        info = self._lookup_single(ip)
        self.cache[ip] = info
        return info

    # -- internals ---------------------------------------------------------

    def _lookup_batch(self, ips: Sequence[str]) -> dict[str, GeoInfo]:
        self._limiter.wait()
        try:
            response = self.session.post(
                self.settings.batch_url,
                json=list(ips),
                timeout=self.settings.timeout_seconds,
                headers={"User-Agent": HTTP_USER_AGENT},
            )
            payload = response.json()
        except Exception as exc:
            logger.warning(
                "geo batch lookup failed (%s) for %d IPs",
                type(exc).__name__,
                len(ips),
            )
            return {ip: GeoInfo() for ip in ips}

        results: dict[str, GeoInfo] = {}
        if not isinstance(payload, list):
            return {ip: GeoInfo() for ip in ips}
        for item in payload:
            if not isinstance(item, dict):
                continue
            ip = str(item.get("query") or "")
            if not ip or ip not in ips:
                continue
            if str(item.get("status") or "") == "success" and item.get("countryCode"):
                info = GeoInfo(
                    country_code=str(item["countryCode"]).upper(),
                    country_name=str(item.get("country") or UNKNOWN_NAME),
                )
            else:
                info = GeoInfo()
            results[ip] = info
        for ip in ips:
            results.setdefault(ip, GeoInfo())
        return results

    def _lookup_single(self, ip: str) -> GeoInfo:
        self._limiter.wait()
        try:
            response = self.session.get(
                self.settings.single_url.format(ip=ip),
                timeout=self.settings.timeout_seconds,
                headers={"User-Agent": HTTP_USER_AGENT},
            )
            payload = response.json()
            if (
                isinstance(payload, dict)
                and str(payload.get("status") or "") == "success"
                and payload.get("countryCode")
            ):
                return GeoInfo(
                    country_code=str(payload["countryCode"]).upper(),
                    country_name=str(payload.get("country") or UNKNOWN_NAME),
                )
        except Exception as exc:
            logger.debug(
                "geo single lookup failed for %s: %s",
                redact_text(ip),
                type(exc).__name__,
            )
        return GeoInfo()
