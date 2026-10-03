"""VLESS parser: ``vless://uuid@host:port?params#name``."""

from __future__ import annotations

from ..models import ParsedConfig, ParseError
from . import common


def parse(uri: str) -> ParsedConfig:
    scheme, _ = common.split_scheme(uri)
    if scheme != "vless":
        raise ParseError(f"unexpected scheme for vless parser: {scheme}")
    parts = common.parse_uri_parts(uri)
    return ParsedConfig(
        protocol="vless",
        host=parts.host,
        port=parts.port,
        identity=parts.identity,
        name=parts.name,
        params=parts.params,
        original_uri=uri,
    )
