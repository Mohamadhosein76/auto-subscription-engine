"""TUIC v5 share-link parser.

Common clients (including Hiddify/Neko family) use:
``tuic://<uuid>:<password>@<host>:<port>?...``.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, unquote, urlsplit

from ..models import ParseError, ParsedConfig
from .common import split_host_port, split_scheme


def parse(uri: str) -> ParsedConfig:
    scheme, _ = split_scheme(uri)
    if scheme != "tuic":
        raise ParseError(f"unexpected scheme for tuic parser: {scheme}")
    try:
        parts = urlsplit(uri)
    except ValueError as exc:
        raise ParseError(f"unparseable URI: {exc}") from exc
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
    else:
        userinfo, hostport = "", netloc
    identity = None
    password = ""
    if userinfo:
        decoded = unquote(userinfo)
        identity, sep, password = decoded.partition(":")
        if not sep:
            # Keep UUID for structural validation; missing password is reported there.
            identity = decoded
            password = ""
    host, port = split_host_port(hostport)
    params = {k: v for k, v in parse_qsl(parts.query, keep_blank_values=True)}
    if password:
        params["password"] = password
    name = unquote(parts.fragment).strip() if parts.fragment else None
    return ParsedConfig(
        protocol="tuic",
        host=host,
        port=port,
        identity=identity or None,
        name=name or None,
        params=params,
        original_uri=uri,
    )
