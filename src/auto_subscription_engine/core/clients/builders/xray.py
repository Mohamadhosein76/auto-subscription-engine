"""Xray-core config builder (v2rayNG / v2rayN family, spec items 4/27).

Maps a parsed node onto a real Xray JSON config:

- local HTTP inbound (CONNECT-capable) on a private 127.0.0.1 port —
  the runtime tester speaks plain HTTP-CONNECT to it;
- one outbound per node: vless / vmess / trojan / shadowsocks;
- streamSettings: tcp/ws/grpc/h2/httpupgrade (+xhttp where Xray
  supports it), security none/tls/reality with SNI, ALPN, uTLS
  fingerprint, Reality public key / short id / spiderX.

Xray-specific audit rules enforced here (no semantic rewrites):

- ``allowInsecure`` is honoured only as ``insecure``/``allowInsecure=1``
  and copied verbatim; hostname verification is never weakened silently;
- Reality fields are copied 1:1 (publicKey/shortId/spiderX);
- flows other than ``xtls-rprx-vision`` are refused, not reinterpreted;
- Shadowsocks plugins are refused (Xray runs no SS plugins);
- hysteria2 is refused (``unsupported_protocol``) — it must never leak
  into the v2rayNG feed just because sing-box passed it.
"""

from __future__ import annotations

import logging

from ...models import ParsedConfig
from ...network import is_ip_literal
from .singbox import UnsupportedNodeError, _param

logger = logging.getLogger(__name__)

#: Flows Xray accepts on VLESS (anything else is refused, not rewritten).
SUPPORTED_FLOWS = frozenset({"", "xtls-rprx-vision"})


def build_xray_config(
    config: ParsedConfig,
    *,
    listen_port: int,
    resolved_ip: str | None = None,
) -> dict:
    """Build a complete Xray config for one node (may raise UnsupportedNodeError)."""
    outbound = build_xray_outbound(config, resolved_ip=resolved_ip)
    return {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": int(listen_port),
                "protocol": "http",
                "settings": {"allowTransparent": False},
            }
        ],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }


def build_xray_outbound(
    config: ParsedConfig, *, resolved_ip: str | None = None
) -> dict:
    """Build the Xray outbound for one node."""
    server = resolved_ip or (config.host or "")
    port = int(config.port or 0)
    identity = (config.identity or "").strip()
    if not server or not port:
        raise UnsupportedNodeError("missing endpoint")

    protocol = config.protocol
    params = config.params

    if protocol == "vless":
        flow = _param(params, "flow")
        if flow not in SUPPORTED_FLOWS:
            raise UnsupportedNodeError(f"unsupported_option:flow:{flow}")
        user: dict = {"id": identity, "encryption": "none", "level": 0}
        if flow:
            user["flow"] = flow
        outbound: dict = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{"address": server, "port": port, "users": [user]}]},
        }
        outbound["streamSettings"] = _stream_settings(config)
        return outbound

    if protocol == "vmess":
        user = {
            "id": identity,
            "alterId": int(_param(params, "aid", "alterId") or 0),
            "security": _param(params, "scy", "security") or "auto",
            "level": 0,
        }
        outbound = {
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {"vnext": [{"address": server, "port": port, "users": [user]}]},
        }
        outbound["streamSettings"] = _stream_settings(config)
        return outbound

    if protocol == "trojan":
        outbound = {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [{"address": server, "port": port, "password": identity, "level": 0}]
            },
        }
        outbound["streamSettings"] = _stream_settings(config)
        return outbound

    if protocol == "ss":
        plugin = _param(params, "plugin")
        if plugin:
            raise UnsupportedNodeError(f"unsupported_option:ss_plugin:{plugin.split(';', 1)[0]}")
        method, _, password = identity.partition(":")
        if not method or not password:
            raise UnsupportedNodeError("malformed shadowsocks identity")
        return {
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {"address": server, "port": port, "method": method, "password": password}
                ]
            },
        }

    raise UnsupportedNodeError(f"unsupported_protocol:{protocol}")


def _stream_settings(config: ParsedConfig) -> dict:
    """Map URI transport/TLS params onto Xray streamSettings."""
    params = config.params
    net_raw = _param(params, "type", "net").lower() or "tcp"
    security = _param(params, "security").lower()
    if config.protocol == "vmess":
        net_raw = _param(params, "net", "type").lower() or net_raw
        security = "tls" if _param(params, "tls").lower() == "tls" else security

    stream: dict = {"network": _NETWORK_NAMES.get(net_raw, net_raw)}

    if net_raw == "ws":
        ws: dict = {"path": _param(params, "path") or "/"}
        host = _param(params, "host")
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif net_raw == "grpc":
        service = _param(params, "servicename", "service_name") or _param(params, "path")
        stream["grpcSettings"] = {"serviceName": service or "", "multiMode": False}
    elif net_raw in ("h2", "http"):
        h2: dict = {"path": _param(params, "path") or "/"}
        host = _param(params, "host")
        if host:
            h2["host"] = [host]
        stream["httpSettings"] = h2
    elif net_raw == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": _param(params, "path") or "/",
            "host": _param(params, "host"),
        }
    elif net_raw == "xhttp":
        stream["xhttpSettings"] = {
            "path": _param(params, "path") or "/",
            "host": _param(params, "host"),
            "mode": "auto",
        }
    elif net_raw in ("tcp", "raw", "none", ""):
        pass
    else:
        raise UnsupportedNodeError(f"unsupported_transport:{net_raw}")

    if security == "reality":
        pbk = _param(params, "pbk")
        if not pbk:
            raise UnsupportedNodeError("unsupported_option:reality_without_pbk")
        reality: dict = {
            "serverName": _sni(config),
            "fingerprint": _param(params, "fp") or "chrome",
            "publicKey": pbk,
            "show": False,
        }
        sid = _param(params, "sid")
        if sid:
            reality["shortId"] = sid
        spx = _param(params, "spx")
        if spx:
            reality["spiderX"] = spx
        stream["security"] = "reality"
        stream["realitySettings"] = reality
    elif security == "tls" or (config.protocol == "trojan") or (
        config.protocol == "vmess" and _param(params, "tls").lower() == "tls"
    ):
        tls: dict = {"serverName": _sni(config), "allowInsecure": False}
        alpn = _param(params, "alpn")
        if alpn:
            items = [item.strip() for item in alpn.split(",") if item.strip()]
            if items:
                tls["alpn"] = items
        fingerprint = _param(params, "fp")
        if fingerprint:
            tls["fingerprint"] = fingerprint
        allow_insecure = _param(params, "insecure", "allowinsecure", "allow_insecure").lower()
        if allow_insecure in ("1", "true"):
            # Honoured verbatim (user opted into skipping verification);
            # never enabled by the engine itself.
            tls["allowInsecure"] = True
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif security in ("none", ""):
        stream["security"] = "none"
    else:
        raise UnsupportedNodeError(f"unsupported_option:security:{security}")
    return stream


def _sni(config: ParsedConfig) -> str:
    """SNI for TLS/Reality: explicit sni/peer/host, else the hostname."""
    sni = _param(config.params, "sni", "peer", "host")
    if not sni and config.host and not is_ip_literal(config.host):
        sni = config.host
    return sni or ""


_NETWORK_NAMES = {"h2": "http"}  # Xray calls the h2 transport "http"
