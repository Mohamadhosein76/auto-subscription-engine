"""Hysteria2 parser: ``hysteria2://password@host:port/?params#name``.

``hy2://`` is accepted as an alias. Per the official URI scheme the port
is optional and defaults to 443.
"""

from __future__ import annotations

from ..models import ParsedConfig, ParseError
from . import common

_SCHEMES = ("hysteria2", "hy2")
_DEFAULT_PORT = 443


def parse(uri: str) -> ParsedConfig:
    scheme, _ = common.split_scheme(uri)
    if scheme not in _SCHEMES:
        raise ParseError(f"unexpected scheme for hysteria2 parser: {scheme}")
    parts = common.parse_uri_parts(uri)
    port = parts.port if parts.port is not None else _DEFAULT_PORT
    return ParsedConfig(
        protocol="hysteria2",
        host=parts.host,
        port=port,
        identity=parts.identity,
        name=parts.name,
        params=parts.params,
        original_uri=uri,
    )
