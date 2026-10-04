"""Native sing-box per-node builder used by NekoBox/Hiddify/runtime tests.

Pinned core installation lives in :mod:`auto_subscription_engine.core.clients.install`;
this module owns only config construction and local-port allocation.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
from collections import deque
from pathlib import Path

from ...models import ParsedConfig
from ...network import is_ip_literal

logger = logging.getLogger(__name__)


class UnsupportedNodeError(Exception):
    """Raised when a parsed config cannot be represented faithfully."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


_RECENT_PORT_LIMIT = 512
_RECENT_PORTS: deque[int] = deque()
_RECENT_PORT_SET: set[int] = set()
_PORT_LOCK = threading.Lock()


def allocate_port() -> int:
    """Return a recently-unused OS-assigned localhost port.

    Binding to port ``0`` is the correct way to ask the kernel for an ephemeral
    port, but the port becomes reusable as soon as that probe socket closes. A
    fast caller could therefore receive the same number twice before the core
    has had a chance to bind it. Keep a bounded, process-local history and retry
    duplicate assignments so concurrent/rapid core launches never collide with
    another port just handed out by ASE.

    This cannot reserve the port against unrelated external processes (the
    proxy cores do not accept inherited listener sockets), so the core startup
    health check remains the authority for the final bind result.
    """
    with _PORT_LOCK:
        for _ in range(64):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(("127.0.0.1", 0))
                port = int(sock.getsockname()[1])
            finally:
                sock.close()

            if port in _RECENT_PORT_SET:
                continue

            if len(_RECENT_PORTS) >= _RECENT_PORT_LIMIT:
                expired = _RECENT_PORTS.popleft()
                _RECENT_PORT_SET.discard(expired)
            _RECENT_PORTS.append(port)
            _RECENT_PORT_SET.add(port)
            return port

    raise RuntimeError("unable to allocate a unique ephemeral localhost port")


# ---------------------------------------------------------------------------
# Per-node core configuration
# ---------------------------------------------------------------------------


def _param(params: dict[str, str], *names: str) -> str:
    """Case-insensitive parameter lookup."""
    lowered = {key.lower(): value for key, value in params.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value:
            return value
    return ""



def _tls_block(
    config: ParsedConfig,
    *,
    enabled: bool = True,
    sni_override: str = "",
    allow_insecure: bool = False,
) -> dict:
    """Build a sing-box TLS block from URI params."""
    host = config.host or ""
    sni = sni_override or _param(config.params, "sni", "peer", "host")
    if not sni and not is_ip_literal(host):
        sni = host
    block: dict = {"enabled": enabled}
    if sni:
        block["server_name"] = sni
    if allow_insecure:
        block["insecure"] = True
    alpn = _param(config.params, "alpn")
    if alpn:
        items = [item.strip() for item in alpn.split(",") if item.strip()]
        if items:
            block["alpn"] = items
    fingerprint = _param(config.params, "fp")
    if fingerprint:
        block["utls"] = {"enabled": True, "fingerprint": fingerprint}
    pbk = _param(config.params, "pbk")
    if pbk:
        reality: dict = {"enabled": True, "public_key": pbk}
        sid = _param(config.params, "sid")
        if sid:
            reality["short_id"] = sid
        block["reality"] = reality
    return block


def _transport_block(params: dict[str, str]) -> dict | None:
    """Map URI transport params onto a sing-box transport block."""
    net = _param(params, "type", "net").lower() or "tcp"
    path = _param(params, "path")
    host = _param(params, "host")
    service = _param(params, "servicename", "service_name") or path

    if net in ("tcp", "raw", "none", ""):
        return None
    if net == "ws":
        transport: dict = {"type": "ws", "path": path or "/"}
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if net == "grpc":
        return {"type": "grpc", "service_name": service or ""}
    if net in ("h2", "http"):
        transport = {"type": "http", "path": path or "/"}
        if host:
            transport["host"] = [host]
        return transport
    if net == "httpupgrade":
        transport = {"type": "httpupgrade", "path": path or "/"}
        if host:
            transport["host"] = host
        return transport
    raise UnsupportedNodeError(f"unsupported transport: {net}")


def build_outbound(config: ParsedConfig, resolved_ip: str | None = None) -> dict:
    """Map a parsed config onto a sing-box outbound definition.

    ``resolved_ip`` (from the TCP precheck) is used as the server address
    so the core does not need its own DNS resolution; the original
    hostname stays available as the TLS SNI.
    """
    server = resolved_ip or (config.host or "")
    port = int(config.port or 0)
    identity = (config.identity or "").strip()
    if not server or not port:
        raise UnsupportedNodeError("missing endpoint")

    protocol = config.protocol

    if protocol == "vless":
        outbound: dict = {
            "type": "vless",
            "tag": "proxy",
            "server": server,
            "server_port": port,
            "uuid": identity,
        }
        flow = _param(config.params, "flow")
        if flow:
            outbound["flow"] = flow
        security = _param(config.params, "security").lower()
        if security in ("tls", "reality"):
            outbound["tls"] = _tls_block(config)
            if security == "reality":
                outbound["tls"].setdefault("reality", {"enabled": True})
                outbound["tls"]["reality"]["enabled"] = True
        transport = _transport_block(config.params)
        if transport is not None:
            outbound["transport"] = transport
        return outbound

    if protocol == "vmess":
        outbound = {
            "type": "vmess",
            "tag": "proxy",
            "server": server,
            "server_port": port,
            "uuid": identity,
            "security": _param(config.params, "scy", "security") or "auto",
            "alter_id": int(_param(config.params, "aid", "alterId") or 0),
        }
        if _param(config.params, "tls").lower() == "tls":
            outbound["tls"] = _tls_block(config)
        transport = _transport_block(config.params)
        if transport is not None:
            outbound["transport"] = transport
        return outbound

    if protocol == "trojan":
        outbound = {
            "type": "trojan",
            "tag": "proxy",
            "server": server,
            "server_port": port,
            "password": identity,
            "tls": _tls_block(config),
        }
        transport = _transport_block(config.params)
        if transport is not None:
            outbound["transport"] = transport
        return outbound

    if protocol == "ss":
        plugin = _param(config.params, "plugin")
        if plugin:
            raise UnsupportedNodeError("ss plugins are not supported for live testing")
        method, _, password = identity.partition(":")
        if not method or not password:
            raise UnsupportedNodeError("malformed shadowsocks identity")
        return {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": server,
            "server_port": port,
            "method": method,
            "password": password,
        }

    if protocol == "hysteria2":
        allow_insecure = _param(config.params, "insecure", "allowinsecure").lower() in (
            "1",
            "true",
        )
        outbound = {
            "type": "hysteria2",
            "tag": "proxy",
            "server": server,
            "server_port": port,
            "password": identity,
            "tls": _tls_block(config, allow_insecure=allow_insecure),
        }
        obfs = _param(config.params, "obfs").lower()
        if obfs == "salamander":
            outbound["obfs"] = {
                "type": "salamander",
                "password": _param(config.params, "obfs-password", "obfsparam"),
            }
        return outbound

    if protocol == "tuic":
        password = _param(config.params, "password")
        if not identity or not password:
            raise UnsupportedNodeError("malformed tuic identity")
        allow_insecure = _param(
            config.params, "insecure", "allowinsecure", "allow_insecure"
        ).lower() in ("1", "true")
        outbound = {
            "type": "tuic",
            "tag": "proxy",
            "server": server,
            "server_port": port,
            "uuid": identity,
            "password": password,
            "congestion_control": _param(
                config.params, "congestion_control", "congestion-controller"
            ) or "cubic",
            "udp_relay_mode": _param(
                config.params, "udp_relay_mode", "udp-relay-mode"
            ) or "native",
            "tls": _tls_block(config, allow_insecure=allow_insecure),
        }
        reduce_rtt = _param(config.params, "reduce_rtt", "reduce-rtt").lower()
        if reduce_rtt in ("1", "true"):
            outbound["zero_rtt_handshake"] = True
        return outbound

    raise UnsupportedNodeError(f"protocol not testable: {protocol}")


def build_node_config(
    config: ParsedConfig, *, listen_port: int, resolved_ip: str | None = None
) -> dict:
    """Build the full per-node sing-box config (mixed inbound + one outbound)."""
    outbound = build_outbound(config, resolved_ip)
    return {
        "log": {"level": "error", "timestamp": False},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": int(listen_port),
            }
        ],
        "outbounds": [outbound],
        "route": {"final": "proxy"},
    }


def write_node_config(config: dict, workdir: Path) -> Path:
    """Write the node config into ``workdir`` with owner-only permissions."""
    workdir = Path(workdir)
    path = workdir / "config.json"
    text = json.dumps(config, indent=2, ensure_ascii=False)
    path.write_text(text, encoding="utf-8", newline="\n")
    from ...platform.paths import set_owner_only_permissions

    set_owner_only_permissions(path)
    return path
