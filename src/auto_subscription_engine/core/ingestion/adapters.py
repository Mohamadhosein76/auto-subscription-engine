"""Adapters from structured client formats to the ASE canonical model."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..models import OriginFormat, ParsedConfig, legacy_to_canonical

STRUCTURED_PROTOCOLS = frozenset(
    {"vless", "vmess", "trojan", "ss", "hysteria2", "tuic"}
)

_CLASH_KNOWN_FIELDS = frozenset(
    {
        "name",
        "type",
        "server",
        "port",
        "uuid",
        "password",
        "auth",
        "cipher",
        "network",
        "tls",
        "sni",
        "servername",
        "skip-cert-verify",
        "alpn",
        "client-fingerprint",
        "ws-opts",
        "grpc-opts",
        "reality-opts",
        "plugin",
        "plugin-opts",
        "obfs",
        "obfs-password",
        "congestion-controller",
        "udp-relay-mode",
        "reduce-rtt",
    }
)


def from_clash_proxy(
    obj: dict[str, Any], source: str = ""
):
    """Convert one Clash/Mihomo proxy mapping into a canonical proxy."""
    protocol = _normalize_protocol(obj.get("type"))
    if protocol not in STRUCTURED_PROTOCOLS:
        return None

    params: dict[str, Any] = {}
    identity = _clash_identity(protocol, obj, params)
    _map_clash_transport(protocol, obj, params)
    _map_clash_tls(protocol, obj, params)
    _map_clash_protocol_options(protocol, obj, params)

    canonical = _canonical_from_legacy(
        protocol=protocol,
        host=obj.get("server"),
        port=obj.get("port"),
        identity=identity,
        name=obj.get("name"),
        params=params,
        fmt=OriginFormat.CLASH_YAML,
        source=source,
    )
    canonical.extra_fields = {
        str(key): value
        for key, value in obj.items()
        if key not in _CLASH_KNOWN_FIELDS
    }
    return canonical


def from_singbox_outbound(
    obj: dict[str, Any], source: str = ""
):
    """Convert one sing-box outbound mapping into a canonical proxy."""
    protocol = _normalize_protocol(obj.get("type"))
    if protocol not in STRUCTURED_PROTOCOLS:
        return None

    params: dict[str, Any] = {}
    identity = _singbox_identity(protocol, obj, params)
    _map_singbox_transport(protocol, obj, params)
    _map_singbox_tls(protocol, obj, params)
    _map_singbox_protocol_options(protocol, obj, params)

    return _canonical_from_legacy(
        protocol=protocol,
        host=obj.get("server"),
        port=obj.get("server_port"),
        identity=identity,
        name=obj.get("tag"),
        params=params,
        fmt=OriginFormat.SINGBOX_JSON,
        source=source,
    )


def from_xray_outbound(
    obj: dict[str, Any], source: str = ""
) -> list:
    """Expand one Xray outbound into zero or more canonical proxies."""
    protocol = _normalize_protocol(obj.get("protocol"))
    if protocol not in {"vless", "vmess", "trojan", "ss"}:
        return []

    settings = _mapping(obj.get("settings"))
    params = _xray_stream_params(protocol, _mapping(obj.get("streamSettings")))

    if protocol in {"vless", "vmess"}:
        return _expand_xray_vnext(
            protocol=protocol,
            settings=settings,
            params=params,
            tag=obj.get("tag"),
            source=source,
        )

    return _expand_xray_servers(
        protocol=protocol,
        settings=settings,
        params=params,
        tag=obj.get("tag"),
        source=source,
    )


def _canonical_from_legacy(
    *,
    protocol: str,
    host: Any,
    port: Any,
    identity: str,
    name: Any,
    params: dict[str, Any],
    fmt: OriginFormat,
    source: str,
):
    normalized_params = {
        str(key): _string(value)
        for key, value in params.items()
        if value is not None and value != ""
    }
    legacy = ParsedConfig(
        protocol=protocol,
        host=_string(host).strip().lower() or None,
        port=_port(port),
        identity=identity or None,
        name=_string(name).strip() or None,
        params=normalized_params,
        source=source,
    )
    return legacy_to_canonical(legacy, origin_format=fmt)


def _clash_identity(
    protocol: str,
    obj: dict[str, Any],
    params: dict[str, Any],
) -> str:
    if protocol in {"vless", "vmess"}:
        return _string(obj.get("uuid"))
    if protocol in {"trojan", "hysteria2"}:
        return _string(obj.get("password", obj.get("auth")))
    if protocol == "ss":
        return f"{_string(obj.get('cipher'))}:{_string(obj.get('password'))}"

    params["password"] = _string(obj.get("password"))
    return _string(obj.get("uuid"))


def _map_clash_transport(
    protocol: str,
    obj: dict[str, Any],
    params: dict[str, Any],
) -> None:
    network = _string(obj.get("network"))
    if network:
        params["net" if protocol == "vmess" else "type"] = network

    ws_options = _mapping(obj.get("ws-opts"))
    if ws_options:
        if ws_options.get("path"):
            params["path"] = _string(ws_options["path"])
        headers = _mapping(ws_options.get("headers"))
        host = headers.get("Host", headers.get("host"))
        if host:
            params["host"] = _string(host)

    grpc_options = _mapping(obj.get("grpc-opts"))
    if grpc_options:
        service_name = grpc_options.get(
            "grpc-service-name", grpc_options.get("service-name")
        )
        if service_name:
            params["serviceName"] = _string(service_name)


def _map_clash_tls(
    protocol: str,
    obj: dict[str, Any],
    params: dict[str, Any],
) -> None:
    if obj.get("tls") is True:
        params["tls" if protocol == "vmess" else "security"] = "tls"

    sni = obj.get("sni", obj.get("servername"))
    if sni:
        params["sni"] = _string(sni)

    if obj.get("skip-cert-verify") is True:
        params["allow_insecure"] = "1"

    alpn = obj.get("alpn")
    if alpn:
        params["alpn"] = _csv(alpn)

    if obj.get("client-fingerprint"):
        params["fp"] = _string(obj["client-fingerprint"])

    reality = _mapping(obj.get("reality-opts"))
    if reality:
        params["security"] = "reality"
        if reality.get("public-key"):
            params["pbk"] = _string(reality["public-key"])
        if reality.get("short-id"):
            params["sid"] = _string(reality["short-id"])


def _map_clash_protocol_options(
    protocol: str,
    obj: dict[str, Any],
    params: dict[str, Any],
) -> None:
    if protocol == "ss" and obj.get("plugin"):
        params["plugin"] = _string(obj["plugin"])
        if obj.get("plugin-opts") is not None:
            params["plugin-opts"] = _string(obj["plugin-opts"])

    if protocol == "hysteria2":
        if obj.get("obfs"):
            params["obfs"] = _string(obj["obfs"])
        if obj.get("obfs-password"):
            params["obfs-password"] = _string(obj["obfs-password"])

    if protocol == "tuic":
        if obj.get("congestion-controller"):
            params["congestion_control"] = _string(
                obj["congestion-controller"]
            )
        if obj.get("udp-relay-mode"):
            params["udp_relay_mode"] = _string(obj["udp-relay-mode"])
        if obj.get("reduce-rtt") is True:
            params["reduce_rtt"] = "1"


def _singbox_identity(
    protocol: str,
    obj: dict[str, Any],
    params: dict[str, Any],
) -> str:
    if protocol in {"vless", "vmess"}:
        return _string(obj.get("uuid"))
    if protocol in {"trojan", "hysteria2"}:
        return _string(obj.get("password"))
    if protocol == "ss":
        return f"{_string(obj.get('method'))}:{_string(obj.get('password'))}"

    params["password"] = _string(obj.get("password"))
    return _string(obj.get("uuid"))


def _map_singbox_transport(
    protocol: str,
    obj: dict[str, Any],
    params: dict[str, Any],
) -> None:
    transport = _mapping(obj.get("transport"))
    if not transport:
        return

    if transport.get("type"):
        params["net" if protocol == "vmess" else "type"] = _string(
            transport["type"]
        )
    if transport.get("path"):
        params["path"] = _string(transport["path"])
    if transport.get("service_name"):
        params["serviceName"] = _string(transport["service_name"])

    headers = _mapping(transport.get("headers"))
    if headers.get("Host"):
        params["host"] = _string(headers["Host"])


def _map_singbox_tls(
    protocol: str,
    obj: dict[str, Any],
    params: dict[str, Any],
) -> None:
    tls = _mapping(obj.get("tls"))
    if not tls or tls.get("enabled", True) is False:
        return

    reality = _mapping(tls.get("reality"))
    security = "reality" if reality.get("enabled") else "tls"
    params["tls" if protocol == "vmess" else "security"] = security

    if tls.get("server_name"):
        params["sni"] = _string(tls["server_name"])
    if tls.get("insecure") is True:
        params["allow_insecure"] = "1"
    if tls.get("alpn"):
        params["alpn"] = _csv(tls["alpn"])

    utls = _mapping(tls.get("utls"))
    if utls.get("fingerprint"):
        params["fp"] = _string(utls["fingerprint"])

    if reality.get("public_key"):
        params["pbk"] = _string(reality["public_key"])
    if reality.get("short_id"):
        params["sid"] = _string(reality["short_id"])


def _map_singbox_protocol_options(
    protocol: str,
    obj: dict[str, Any],
    params: dict[str, Any],
) -> None:
    if protocol == "vmess":
        params["scy"] = _string(obj.get("security", "auto"))
        params["aid"] = _string(obj.get("alter_id", 0))

    if protocol == "hysteria2":
        obfs = _mapping(obj.get("obfs"))
        if obfs.get("type"):
            params["obfs"] = _string(obfs["type"])
        if obfs.get("password"):
            params["obfs-password"] = _string(obfs["password"])

    if protocol == "tuic":
        params["congestion_control"] = _string(
            obj.get("congestion_control", "cubic")
        )
        params["udp_relay_mode"] = _string(
            obj.get("udp_relay_mode", "native")
        )


def _xray_stream_params(
    protocol: str,
    stream: dict[str, Any],
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    network = _string(stream.get("network", "tcp"))
    params["net" if protocol == "vmess" else "type"] = network

    security = _string(stream.get("security"))
    if security:
        params["tls" if protocol == "vmess" else "security"] = security

    tls = _mapping(stream.get("tlsSettings"))
    reality = _mapping(stream.get("realitySettings"))
    security_settings = tls or reality

    if security_settings.get("serverName"):
        params["sni"] = _string(security_settings["serverName"])
    if security_settings.get("alpn"):
        params["alpn"] = _csv(security_settings["alpn"])
    if security_settings.get("fingerprint"):
        params["fp"] = _string(security_settings["fingerprint"])

    if reality:
        params["security"] = "reality"
        if reality.get("publicKey"):
            params["pbk"] = _string(reality["publicKey"])
        if reality.get("shortId"):
            params["sid"] = _string(reality["shortId"])
        if reality.get("spiderX"):
            params["spx"] = _string(reality["spiderX"])

    ws_settings = _mapping(stream.get("wsSettings"))
    if ws_settings:
        if ws_settings.get("path"):
            params["path"] = _string(ws_settings["path"])
        headers = _mapping(ws_settings.get("headers"))
        if headers.get("Host"):
            params["host"] = _string(headers["Host"])

    grpc_settings = _mapping(stream.get("grpcSettings"))
    if grpc_settings.get("serviceName"):
        params["serviceName"] = _string(grpc_settings["serviceName"])

    return params


def _expand_xray_vnext(
    *,
    protocol: str,
    settings: dict[str, Any],
    params: dict[str, Any],
    tag: Any,
    source: str,
) -> list:
    result = []
    vnext_entries = settings.get("vnext")
    if not isinstance(vnext_entries, list):
        return result

    for vnext in vnext_entries:
        if not isinstance(vnext, dict):
            continue
        users = vnext.get("users")
        if not isinstance(users, list):
            continue

        for user in users:
            if not isinstance(user, dict):
                continue
            user_params = dict(params)
            if protocol == "vless" and user.get("flow"):
                user_params["flow"] = _string(user["flow"])
            if protocol == "vmess":
                user_params["aid"] = _string(user.get("alterId", 0))
                user_params["scy"] = _string(user.get("security", "auto"))

            result.append(
                _canonical_from_legacy(
                    protocol=protocol,
                    host=vnext.get("address"),
                    port=vnext.get("port"),
                    identity=_string(user.get("id")),
                    name=tag,
                    params=user_params,
                    fmt=OriginFormat.XRAY_JSON,
                    source=source,
                )
            )
    return result


def _expand_xray_servers(
    *,
    protocol: str,
    settings: dict[str, Any],
    params: dict[str, Any],
    tag: Any,
    source: str,
) -> list:
    result = []
    servers = settings.get("servers")
    if not isinstance(servers, list):
        return result

    for server in servers:
        if not isinstance(server, dict):
            continue
        if protocol == "trojan":
            identity = _string(server.get("password"))
        else:
            identity = (
                f"{_string(server.get('method'))}:"
                f"{_string(server.get('password'))}"
            )
        result.append(
            _canonical_from_legacy(
                protocol=protocol,
                host=server.get("address"),
                port=server.get("port"),
                identity=identity,
                name=tag,
                params=params,
                fmt=OriginFormat.XRAY_JSON,
                source=source,
            )
        )
    return result


def _normalize_protocol(value: Any) -> str:
    protocol = _string(value).strip().lower()
    aliases = {
        "hy2": "hysteria2",
        "shadowsocks": "ss",
    }
    return aliases.get(protocol, protocol)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string(value: Any) -> str:
    return "" if value is None else str(value)


def _port(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _csv(value: Any) -> str:
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes, dict)):
        return ",".join(str(item) for item in value)
    return _string(value)
