"""VMess parser.

The canonical format is ``vmess://<base64-encoded JSON object>`` with
fields such as ``add`` (host), ``port``, ``id`` (UUID), ``ps`` (display
name), ``net``/``type``/``host``/``path``/``tls``/``sni``.

Decoding is deliberately robust: standard or URL-safe base64, with or
without padding, wrapped across lines, or even raw JSON — plus a
fallback for the non-standard URI-style ``vmess://uuid@host:port`` form
emitted by some clients (``@`` can never appear in base64, so the two
shapes are unambiguous).
"""

from __future__ import annotations

import json

from ..utils.base64 import robust_b64decode
from ..models import ParsedConfig, ParseError
from . import common

#: JSON fields copied into ``params`` (transport/behaviour metadata).
_PARAM_FIELDS = ("aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp")
#: Fields consumed elsewhere in the model (identity/name/endpoint).
_CONSUMED_FIELDS = ("id", "ps", "add", "address", "server", "port", "v")
_HOST_FIELDS = ("add", "address", "server")


def parse(uri: str) -> ParsedConfig:
    scheme, payload = common.split_scheme(uri)
    if scheme != "vmess":
        raise ParseError(f"unexpected scheme for vmess parser: {scheme}")

    if "@" in payload:
        # URI-style (non-standard but seen in the wild): vmess://uuid@host:port
        parts = common.parse_uri_parts(uri)
        return ParsedConfig(
            protocol="vmess",
            host=parts.host,
            port=parts.port,
            identity=parts.identity,
            name=parts.name,
            params=parts.params,
            original_uri=uri,
        )

    text = payload.strip()
    if text.startswith("{"):
        json_text = text
    else:
        decoded = robust_b64decode(text)
        if decoded is None:
            raise ParseError("invalid base64 payload")
        json_text = decoded

    try:
        obj = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON payload: {exc.msg}") from exc
    if not isinstance(obj, dict):
        raise ParseError("vmess payload is not a JSON object")

    host = _extract_host(obj)
    port = _extract_port(obj)
    identity = str(obj.get("id") or "").strip() or None
    name = str(obj.get("ps") or "").strip() or None

    params: dict[str, str] = {}
    for field in _PARAM_FIELDS:
        value = obj.get(field)
        if value is None:
            continue
        params[field] = str(value)

    # Parser fidelity: JSON fields that are neither consumed nor mapped
    # are preserved verbatim in ``extra_fields`` - never silently
    # dropped - so the compatibility layer can flag them as
    # parser_feature_unsupported instead of faking a PASS.
    extra: dict[str, str] = {}
    for key, value in obj.items():
        if key in _PARAM_FIELDS or key in _CONSUMED_FIELDS:
            continue
        extra[str(key)] = value if isinstance(value, str) else json.dumps(
            value, ensure_ascii=False, sort_keys=True
        )

    return ParsedConfig(
        protocol="vmess",
        host=host,
        port=port,
        identity=identity,
        name=name,
        params=params,
        original_uri=uri,
        extra_fields=extra,
    )


def _extract_host(obj: dict[str, object]) -> str | None:
    for field in _HOST_FIELDS:
        value = obj.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
        if isinstance(value, (int, float)):
            return str(value)
    return None


def _extract_port(obj: dict[str, object]) -> int | None:
    value = obj.get("port")
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ParseError("invalid port value") from exc
