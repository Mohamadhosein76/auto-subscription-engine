"""Safe source URL validation and canonical identifiers."""
from __future__ import annotations

import hashlib
from urllib.parse import SplitResult, urlsplit, urlunsplit

from ..network import is_local_host

_ALLOWED_SCHEMES = frozenset({"http", "https"})


def validate_source_url(url: str) -> str | None:
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return "unparseable URL"
    scheme = (parts.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        return f"scheme must be http or https (got '{scheme or 'none'}')"
    if not host:
        return "missing host"
    if parts.username or parts.password:
        return "embedded credentials are not allowed in source URLs"
    if is_local_host(host):
        return "localhost/private source hosts are not allowed"
    if port is not None and not 1 <= port <= 65535:
        return "port out of range"
    return None


def canonicalize_source_url(url: str) -> str:
    """Normalize transport-safe URL components without reordering query data."""
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    port = parts.port
    if port is not None and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = parts.path or "/"
    normalized = SplitResult(scheme, netloc, path, parts.query, "")
    return urlunsplit(normalized)


def source_id_for_url(url: str) -> str:
    canonical = canonicalize_source_url(url)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]
