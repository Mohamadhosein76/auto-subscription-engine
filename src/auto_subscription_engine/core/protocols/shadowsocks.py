"""Shadowsocks (SS) parser.

Supports both formats seen in the wild:

- **SIP002**: ``ss://<base64url(method:password)>@host:port/?plugin=...#tag``
  (userinfo may also be a percent-encoded plain ``method:password``);
- **Legacy**: ``ss://<base64(method:password@host:port)>#tag``.

The two are unambiguous: ``@`` never appears in a base64 payload, so its
presence in the URI body means SIP002.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, unquote

from ..utils.base64 import robust_b64decode
from ..models import ParsedConfig, ParseError
from .common import split_host_port


def parse(uri: str) -> ParsedConfig:
    scheme, rest = _split_scheme_ss(uri)
    if scheme != "ss":
        raise ParseError(f"unexpected scheme for ss parser: {scheme}")

    main, _, fragment = rest.partition("#")
    main, _, query = main.partition("?")
    params = dict(parse_qsl(query, keep_blank_values=True))
    name = unquote(fragment).strip() if fragment else None

    if "@" in main:
        # SIP002: userinfo@host:port (a path may follow the port).
        userinfo, _, hostport = main.rpartition("@")
        hostport = hostport.split("/", 1)[0]
        method, password = _decode_userinfo(userinfo)
    else:
        # Legacy: the whole body is base64 of "method:password@host:port".
        decoded = robust_b64decode(main)
        if decoded is None or "@" not in decoded:
            raise ParseError("malformed legacy ss payload")
        userinfo, _, hostport = decoded.rpartition("@")
        hostport = hostport.split("/", 1)[0]
        method, password = userinfo.partition(":")[0], userinfo.partition(":")[2]

    if not method:
        raise ParseError("missing ss method")
    host, port = split_host_port(hostport)
    identity = f"{method}:{password}" if password else method or None

    return ParsedConfig(
        protocol="ss",
        host=host,
        port=port,
        identity=identity,
        name=name or None,
        params=params,
        original_uri=uri,
    )


def _split_scheme_ss(uri: str) -> tuple[str, str]:
    if "://" not in uri:
        raise ParseError("missing '://' scheme delimiter")
    scheme, _, rest = uri.partition("://")
    scheme = scheme.strip().lower()
    if not scheme:
        raise ParseError("empty scheme")
    if not rest:
        raise ParseError("empty payload after scheme")
    return scheme, rest


def _decode_userinfo(userinfo: str) -> tuple[str, str]:
    """Decode SIP002 userinfo into (method, password).

    Tries base64url first; falls back to percent-encoded plain text.
    """
    decoded = robust_b64decode(userinfo)
    if decoded is not None and ":" in decoded:
        method, _, password = decoded.partition(":")
        return method, password
    plain = unquote(userinfo)
    if ":" in plain:
        method, _, password = plain.partition(":")
        return method, password
    raise ParseError("missing method/password separator in ss userinfo")
