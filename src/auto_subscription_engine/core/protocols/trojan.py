"""Trojan parser: ``trojan://password@host:port?params#name``."""

from __future__ import annotations

from ..models import ParsedConfig, ParseError
from . import common


def parse(uri: str) -> ParsedConfig:
    scheme, _ = common.split_scheme(uri)
    if scheme != "trojan":
        raise ParseError(f"unexpected scheme for trojan parser: {scheme}")
    parts = common.parse_uri_parts(uri)
    return ParsedConfig(
        protocol="trojan",
        host=parts.host,
        port=parts.port,
        identity=parts.identity,
        name=parts.name,
        params=parts.params,
        original_uri=uri,
    )
