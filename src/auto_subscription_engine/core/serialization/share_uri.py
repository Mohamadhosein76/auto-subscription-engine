"""Serialize canonical proxies into interoperable share URIs."""

from __future__ import annotations

import base64
import json
from urllib.parse import quote, urlencode

from ..models import CanonicalProxy


def to_share_uri(config: CanonicalProxy) -> str:
    """Serialize one canonical proxy into a common share-link representation."""
    protocol = config.protocol
    if protocol == "vmess":
        return _vmess(config)
    if protocol == "ss":
        return _shadowsocks(config)
    if protocol == "tuic":
        return _tuic(config)
    if protocol in {"vless", "trojan", "hysteria2"}:
        return _authority(config)
    raise ValueError(f"no share URI serializer for protocol: {protocol}")


def _authority(config: CanonicalProxy) -> str:
    if config.protocol == "vless":
        identity = config.auth.get("uuid")
    else:
        identity = config.auth.get("password")

    query = _query(_legacy_options(config))
    query_part = f"?{query}" if query else ""
    return (
        f"{config.protocol}://{quote(identity, safe='')}@"
        f"{_format_host(config.host)}:{config.port or ''}"
        f"{query_part}{_fragment(config.name)}"
    )


def _tuic(config: CanonicalProxy) -> str:
    userinfo = f"{config.auth.get('uuid')}:{config.auth.get('password')}"
    options = _legacy_options(config)
    options.pop("password", None)

    if (
        "congestion-controller" in options
        and "congestion_control" not in options
    ):
        options["congestion_control"] = options.pop("congestion-controller")
    if "udp-relay-mode" in options and "udp_relay_mode" not in options:
        options["udp_relay_mode"] = options.pop("udp-relay-mode")

    query = _query(options)
    query_part = f"?{query}" if query else ""
    return (
        f"tuic://{quote(userinfo, safe=':')}@"
        f"{_format_host(config.host)}:{config.port or ''}"
        f"{query_part}{_fragment(config.name)}"
    )


def _shadowsocks(config: CanonicalProxy) -> str:
    credentials = (
        f"{config.auth.get('method')}:{config.auth.get('password')}"
    ).encode("utf-8")
    userinfo = base64.urlsafe_b64encode(credentials).decode("ascii").rstrip("=")

    options = {
        key: value
        for key, value in config.options.items()
        if key == "plugin" and value
    }
    query = _query(options)
    query_part = f"?{query}" if query else ""
    return (
        f"ss://{userinfo}@{_format_host(config.host)}:{config.port or ''}"
        f"{query_part}{_fragment(config.name)}"
    )


def _vmess(config: CanonicalProxy) -> str:
    options = _legacy_options(config)
    payload = {
        "v": "2",
        "ps": config.name or "",
        "add": config.host or "",
        "port": str(config.port or ""),
        "id": config.auth.get("uuid"),
        "aid": str(options.get("aid", "0")),
        "scy": str(options.get("scy", options.get("cipher", "auto"))),
        "net": str(options.get("net", config.transport.kind or "tcp")),
        "type": str(
            options.get("type", config.transport.header_type or "none")
        ),
        "host": str(options.get("host", config.transport.host or "")),
        "path": str(options.get("path", config.transport.path or "")),
        "tls": "tls" if config.tls.enabled else str(options.get("tls", "")),
        "sni": config.tls.server_name or str(options.get("sni", "")),
        "alpn": (
            ",".join(config.tls.alpn)
            if config.tls.alpn
            else str(options.get("alpn", ""))
        ),
        "fp": config.tls.fingerprint or str(options.get("fp", "")),
    }
    blob = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return "vmess://" + base64.b64encode(blob).decode("ascii")


def _legacy_options(config: CanonicalProxy) -> dict[str, object]:
    options: dict[str, object] = dict(config.options)

    if config.transport.kind not in {"", "tcp", "quic"}:
        key = "net" if config.protocol == "vmess" else "type"
        options.setdefault(key, config.transport.kind)
    if config.transport.path:
        options.setdefault("path", config.transport.path)
    if config.transport.host:
        options.setdefault("host", config.transport.host)
    if config.transport.service_name:
        options.setdefault("serviceName", config.transport.service_name)

    if config.tls.mode not in {"", "none"}:
        key = "tls" if config.protocol == "vmess" else "security"
        options.setdefault(key, config.tls.mode)
    if config.tls.server_name:
        options.setdefault("sni", config.tls.server_name)
    if config.tls.alpn:
        options.setdefault("alpn", ",".join(config.tls.alpn))
    if config.tls.fingerprint:
        options.setdefault("fp", config.tls.fingerprint)
    if config.tls.insecure:
        options.setdefault("allow_insecure", "1")
    if config.tls.reality_public_key:
        options.setdefault("pbk", config.tls.reality_public_key)
    if config.tls.reality_short_id:
        options.setdefault("sid", config.tls.reality_short_id)
    if config.tls.reality_spider_x:
        options.setdefault("spx", config.tls.reality_spider_x)

    return options


def _query(options: dict[str, object]) -> str:
    pairs: list[tuple[str, str]] = []
    for key, value in options.items():
        if value is None or value == "":
            continue
        if isinstance(value, (list, tuple)):
            value = ",".join(str(item) for item in value)
        elif isinstance(value, bool):
            value = "1" if value else "0"
        pairs.append((str(key), str(value)))
    return urlencode(pairs, doseq=False, safe="/,:" )


def _format_host(host: str | None) -> str:
    value = host or ""
    if ":" in value and not value.startswith("["):
        return f"[{value}]"
    return value


def _fragment(name: str | None) -> str:
    return f"#{quote(name, safe='')}" if name else ""
