"""Canonical host and IP classification utilities.

This module is the single source of truth for structural hostname checks and
IP classification.  It intentionally performs no network I/O.
"""
from __future__ import annotations

import ipaddress
import re

_HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$"
)

_LOCAL_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}

_LOCAL_SUFFIXES = (
    ".local",
    ".localdomain",
    ".internal",
    ".lan",
    ".home",
    ".arpa",
)


def canonicalize_host(host: str) -> str:
    """Return the canonical textual representation of a host value."""
    cleaned = str(host or "").strip().lower().rstrip(".")
    if not cleaned:
        return ""
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return cleaned


def is_ip_literal(host: str) -> bool:
    """Return True when *host* is a syntactically valid IPv4/IPv6 literal."""
    try:
        ipaddress.ip_address(canonicalize_host(host))
        return True
    except ValueError:
        return False


def ip_version(value: str) -> int | None:
    """Return 4/6 for an IP literal, otherwise ``None``."""
    try:
        return ipaddress.ip_address(canonicalize_host(value)).version
    except ValueError:
        return None


def classify_ip(value: str) -> str:
    """Classify an IP into a stable, security-oriented label."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return "invalid"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved or ip.is_unspecified:
        return "reserved"
    if ip.is_private:
        return "private"
    # Covers non-globally-routable ranges such as shared address space that
    # are neither private nor reserved according to some Python versions.
    if not ip.is_global:
        return "non_global"
    return "public"


def is_bogon(value: str) -> bool:
    """True for any syntactically valid address that is not globally routable."""
    return classify_ip(value) not in ("public", "invalid")


def is_public_ip(value: str) -> bool:
    """Return True only for globally routable IPv4/IPv6 literals."""
    return classify_ip(value) == "public"


def is_local_host(host: str) -> bool:
    """Return True for local-style names and non-global IP literals."""
    cleaned = canonicalize_host(host)
    if not cleaned:
        return True
    if cleaned in _LOCAL_HOSTNAMES:
        return True
    if cleaned.endswith(_LOCAL_SUFFIXES):
        return True
    if is_ip_literal(cleaned):
        return not is_public_ip(cleaned)
    return False


def is_valid_host_format(host: str) -> bool:
    """Structural check: valid IPv4/IPv6 literal or plausible DNS hostname."""
    cleaned = canonicalize_host(host)
    if not cleaned:
        return False
    if is_ip_literal(cleaned):
        return True
    if len(cleaned) > 253:
        return False
    return bool(_HOSTNAME_RE.match(cleaned))
