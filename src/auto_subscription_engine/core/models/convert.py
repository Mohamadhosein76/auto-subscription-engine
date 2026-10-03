"""Conversions between the compatibility model and canonical model."""
from __future__ import annotations

from typing import Any

from .schema import (
    Authentication,
    CanonicalProxy,
    Endpoint,
    OriginFormat,
    ParsedConfig,
    TlsSpec,
    TransportSpec,
)


def _truthy(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def legacy_to_canonical(
    config: ParsedConfig,
    *,
    origin_format: OriginFormat = OriginFormat.URI,
) -> CanonicalProxy:
    p = {str(k).lower(): v for k, v in config.params.items()}
    protocol = config.protocol.lower()
    auth = _auth_from_legacy(protocol, config.identity, p)
    transport = _transport_from_params(protocol, p)
    tls = _tls_from_params(protocol, p)
    options: dict[str, Any] = dict(config.params)
    return CanonicalProxy(
        protocol=protocol,
        endpoint=Endpoint(config.host, config.port),
        auth=auth,
        transport=transport,
        tls=tls,
        name=config.name,
        options=options,
        source=config.source,
        origin_format=origin_format,
        raw=config.original_uri,
        extra_fields=dict(config.extra_fields),
        fingerprint=config.fingerprint,
    )


def canonical_to_legacy(
    config: CanonicalProxy,
    *,
    original_uri: str = "",
) -> ParsedConfig:
    params = _params_from_canonical(config)
    identity = _legacy_identity(config)
    extras = {str(k): _stringify(v) for k, v in config.extra_fields.items()}
    return ParsedConfig(
        protocol=config.protocol,
        host=config.host,
        port=config.port,
        identity=identity or None,
        name=config.name,
        params=params,
        original_uri=original_uri or config.raw,
        fingerprint=config.fingerprint,
        source=config.source,
        extra_fields=extras,
    )


def _auth_from_legacy(
    protocol: str,
    identity: str | None,
    params: dict[str, str],
) -> Authentication:
    identity = identity or ""
    if protocol in {"vless", "vmess"}:
        return Authentication("uuid", {"uuid": identity})
    if protocol in {"trojan", "hysteria2"}:
        return Authentication("password", {"password": identity})
    if protocol == "ss":
        method, sep, password = identity.partition(":")
        return Authentication(
            "shadowsocks",
            {"method": method, "password": password if sep else ""},
        )
    if protocol == "tuic":
        return Authentication(
            "tuic_v5",
            {"uuid": identity, "password": params.get("password", "")},
        )
    return Authentication("opaque", {"identity": identity})


def _transport_from_params(protocol: str, p: dict[str, str]) -> TransportSpec:
    if protocol == "vmess":
        kind = str(p.get("net", "tcp") or "tcp").lower()
    elif protocol in {"vless", "trojan"}:
        kind = str(p.get("type", "tcp") or "tcp").lower()
    else:
        kind = "quic" if protocol in {"hysteria2", "tuic"} else "tcp"
    return TransportSpec(
        kind=kind,
        path=str(p.get("path", "") or ""),
        host=str(p.get("host", "") or ""),
        service_name=str(p.get("servicename", p.get("service_name", "")) or ""),
        header_type=str(p.get("headertype", p.get("header_type", "")) or ""),
    )


def _tls_from_params(protocol: str, p: dict[str, str]) -> TlsSpec:
    security = str(p.get("security", p.get("tls", "")) or "").lower()
    if protocol in {"trojan", "hysteria2", "tuic"} and not security:
        security = "tls"
    alpn = tuple(
        item.strip()
        for item in str(p.get("alpn", "")).split(",")
        if item.strip()
    )
    return TlsSpec(
        enabled=security in {"tls", "reality"},
        mode=security or "none",
        server_name=str(p.get("sni", p.get("servername", "")) or ""),
        alpn=alpn,
        fingerprint=str(p.get("fp", p.get("fingerprint", "")) or ""),
        insecure=_truthy(
            p.get(
                "allow_insecure",
                p.get("allowinsecure", p.get("insecure", "")),
            )
        ),
        reality_public_key=str(p.get("pbk", p.get("publickey", "")) or ""),
        reality_short_id=str(p.get("sid", p.get("shortid", "")) or ""),
        reality_spider_x=str(p.get("spx", p.get("spiderx", "")) or ""),
    )


def _legacy_identity(config: CanonicalProxy) -> str:
    a = config.auth
    if config.protocol in {"vless", "vmess", "tuic"}:
        return a.get("uuid")
    if config.protocol in {"trojan", "hysteria2"}:
        return a.get("password")
    if config.protocol == "ss":
        method, password = a.get("method"), a.get("password")
        return f"{method}:{password}" if method else ""
    return a.get("identity")


def _params_from_canonical(config: CanonicalProxy) -> dict[str, str]:
    params = {
        str(key): _stringify(value)
        for key, value in config.options.items()
        if value is not None
    }
    if config.protocol == "tuic" and config.auth.get("password"):
        params.setdefault("password", config.auth.get("password"))
    if config.transport.kind not in {"", "tcp", "quic"}:
        key = "net" if config.protocol == "vmess" else "type"
        params.setdefault(key, config.transport.kind)
    if config.transport.path:
        params.setdefault("path", config.transport.path)
    if config.transport.host:
        params.setdefault("host", config.transport.host)
    if config.transport.service_name:
        params.setdefault("serviceName", config.transport.service_name)
    if config.tls.mode not in {"", "none"}:
        key = "tls" if config.protocol == "vmess" else "security"
        params.setdefault(key, config.tls.mode)
    if config.tls.server_name:
        params.setdefault("sni", config.tls.server_name)
    if config.tls.alpn:
        params.setdefault("alpn", ",".join(config.tls.alpn))
    if config.tls.fingerprint:
        params.setdefault("fp", config.tls.fingerprint)
    if config.tls.insecure:
        params.setdefault("allow_insecure", "1")
    if config.tls.reality_public_key:
        params.setdefault("pbk", config.tls.reality_public_key)
    if config.tls.reality_short_id:
        params.setdefault("sid", config.tls.reality_short_id)
    if config.tls.reality_spider_x:
        params.setdefault("spx", config.tls.reality_spider_x)
    return params


def _stringify(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value)
    return str(value)
