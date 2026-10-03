"""Shared URI parsing helpers for the per-protocol parsers.

These helpers are deliberately tolerant: structurally broken pieces raise
:class:`ParseError`, while merely *missing* fields (host, port, identity)
flow into the model and are flagged later by the validation stage.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

from ..models import ParseError


@dataclass(frozen=True)
class UriParts:
    """Structural pieces of a ``scheme://userinfo@host:port?query#frag`` URI."""

    identity: str | None
    host: str | None
    port: int | None
    params: dict[str, str]
    name: str | None


def split_scheme(uri: str) -> tuple[str, str]:
    """Split a URI into (lowercased scheme, remainder)."""
    if "://" not in uri:
        raise ParseError("missing '://' scheme delimiter")
    scheme, _, rest = uri.partition("://")
    scheme = scheme.strip().lower()
    if not scheme:
        raise ParseError("empty scheme")
    if not rest:
        raise ParseError("empty payload after scheme")
    return scheme, rest


def parse_uri_parts(uri: str) -> UriParts:
    """Parse userinfo/host/port/query/fragment from an authority-style URI."""
    try:
        parts = urlsplit(uri)
        netloc = parts.netloc
    except ValueError as exc:
        raise ParseError(f"unparseable URI: {exc}") from exc

    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
    else:
        userinfo, hostport = "", netloc

    host, port = split_host_port(hostport)
    identity = unquote(userinfo) if userinfo else None
    params = {
        key: value for key, value in parse_qsl(parts.query, keep_blank_values=True)
    }
    name = unquote(parts.fragment).strip() if parts.fragment else None
    return UriParts(
        identity=identity,
        host=host,
        port=port,
        params=params,
        name=name or None,
    )


def split_host_port(hostport: str) -> tuple[str | None, int | None]:
    """Split ``host:port`` (IPv6 bracket form supported) without range checks.

    A non-numeric port raises :class:`ParseError`; an out-of-range port is
    returned as-is so the validation stage can flag it.
    """
    if not hostport:
        return None, None
    if hostport.startswith("["):
        host, _, rest = hostport[1:].partition("]")
        port_text = rest.lstrip(":")
    elif ":" in hostport:
        host, _, port_text = hostport.rpartition(":")
    else:
        return hostport.lower(), None

    host = host.lower() or None
    if port_text == "":
        return host, None
    if not (port_text.isascii() and port_text.isdigit()):
        raise ParseError("port is not numeric")
    return host, int(port_text)
