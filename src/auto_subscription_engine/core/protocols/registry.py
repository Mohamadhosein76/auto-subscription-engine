"""Central protocol parser registry."""
from __future__ import annotations

from collections.abc import Callable

from ..models import ParseError, ParsedConfig, SCHEME_ALIASES, UnknownProtocolError
from . import common, hysteria2, shadowsocks, trojan, tuic, vless, vmess

MAX_URI_LENGTH = 16384
Parser = Callable[[str], ParsedConfig]

_PARSERS: dict[str, Parser] = {
    "vless": vless.parse,
    "vmess": vmess.parse,
    "trojan": trojan.parse,
    "ss": shadowsocks.parse,
    "hysteria2": hysteria2.parse,
    "tuic": tuic.parse,
}


def register_parser(protocol: str, parser: Parser, *, aliases: tuple[str, ...] = ()) -> None:
    """Register a parser explicitly; used by future protocol plugins."""
    key = protocol.strip().lower()
    if not key:
        raise ValueError("protocol name is empty")
    _PARSERS[key] = parser
    for alias in aliases:
        SCHEME_ALIASES[alias.strip().lower()] = key


def available_protocols() -> tuple[str, ...]:
    return tuple(sorted(_PARSERS))


def parse_uri(uri: str) -> ParsedConfig:
    if len(uri) > MAX_URI_LENGTH:
        raise ParseError("URI exceeds maximum length")
    scheme, _ = common.split_scheme(uri)
    protocol = SCHEME_ALIASES.get(scheme, scheme)
    parser = _PARSERS.get(protocol)
    if parser is None:
        raise UnknownProtocolError(scheme)
    return parser(uri)
