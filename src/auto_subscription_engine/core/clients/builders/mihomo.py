"""Mihomo (Clash.Meta family) config builder, spec items 6/13/28.

Builds a real Mihomo YAML config:

- ``mixed-port`` local proxy (HTTP CONNECT + SOCKS) on 127.0.0.1;
- ``mode: rule`` with a single ``MATCH,proxy`` rule so the tunnel is
  always the tested node (config syntax success alone is never a PASS —
  the runtime tester still pushes real HTTPS traffic through it);
- one proxy per node: vless / vmess / trojan / shadowsocks / hysteria2.

Field mapping notes (audit rules):

- Reality: ``reality-opts: {public-key, short-id}`` + ``client-fingerprint``;
- WS: ``ws-opts: {path, headers: {Host}}`` — Host preserved verbatim;
- gRPC: ``grpc-opts: {grpc-service-name}``;
- SS plugins: only ``obfs``/``v2ray-plugin`` are emitted (Mihomo's real
  plugin set); any other plugin is refused (``unsupported_option``);
- ``skip-cert-verify`` is emitted ONLY when the URI explicitly opts in
  (allowInsecure semantics), never enabled by the engine;
- unique proxy names are the caller's concern (one proxy per config for
  runtime tests; the published YAML uses safe_id-based unique names).
"""

from __future__ import annotations

from ...models import ParsedConfig
from ...network import is_ip_literal
from .singbox import UnsupportedNodeError, _param


def build_mihomo_proxy(
    config: ParsedConfig, *, resolved_ip: str | None = None, name: str = "proxy"
) -> dict:
    """Build one Mihomo proxy mapping (raises UnsupportedNodeError)."""
    server = resolved_ip or (config.host or "")
    port = int(config.port or 0)
    identity = (config.identity or "").strip()
    if not server or not port:
        raise UnsupportedNodeError("missing endpoint")

    params = config.params
    protocol = config.protocol

    if protocol == "vless":
        proxy: dict = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": identity,
            "udp": True,
        }
        flow = _param(params, "flow")
        if flow == "xtls-rprx-vision":
            proxy["flow"] = flow
        elif flow:
            raise UnsupportedNodeError(f"unsupported_option:flow:{flow}")
        _apply_tls_mihomo(proxy, config, protocol)
        _apply_network_mihomo(proxy, config)
        return proxy

    if protocol == "vmess":
        proxy = {
            "name": name,
            "type": "vmess",
            "server": server,
            "port": port,
            "uuid": identity,
            "alterId": int(_param(params, "aid", "alterId") or 0),
            "cipher": _param(params, "scy", "security") or "auto",
            "udp": True,
        }
        if _param(params, "tls").lower() == "tls" or _param(params, "security").lower() in ("tls", "reality"):
            proxy["tls"] = True
        _apply_tls_mihomo(proxy, config, protocol, force_tls=proxy.get("tls"))
        _apply_network_mihomo(proxy, config)
        return proxy

    if protocol == "trojan":
        proxy = {
            "name": name,
            "type": "trojan",
            "server": server,
            "port": port,
            "password": identity,
            "udp": True,
        }
        _apply_tls_mihomo(proxy, config, protocol)
        _apply_network_mihomo(proxy, config)
        return proxy

    if protocol == "ss":
        plugin_raw = _param(params, "plugin")
        method, _, password = identity.partition(":")
        if not method or not password:
            raise UnsupportedNodeError("malformed shadowsocks identity")
        proxy = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
            "udp": True,
        }
        if plugin_raw:
            plugin_name = plugin_raw.split(";", 1)[0].strip().lower()
            if plugin_name not in ("obfs", "v2ray-plugin"):
                raise UnsupportedNodeError(f"unsupported_option:ss_plugin:{plugin_name}")
            proxy["plugin"] = plugin_name
            proxy["plugin-opts"] = _ss_plugin_opts(plugin_name, plugin_raw)
        return proxy

    if protocol == "hysteria2":
        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": identity,
        }
        sni = _param(params, "sni", "peer")
        if sni:
            proxy["sni"] = sni
        if _param(params, "insecure", "allowinsecure").lower() in ("1", "true"):
            proxy["skip-cert-verify"] = True
        obfs = _param(params, "obfs").lower()
        if obfs == "salamander":
            proxy["obfs"] = "salamander"
            proxy["obfs-password"] = _param(params, "obfs-password", "obfsparam")
        alpn = _param(params, "alpn")
        if alpn:
            proxy["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]
        return proxy

    if protocol == "tuic":
        password = _param(params, "password")
        if not identity or not password:
            raise UnsupportedNodeError("malformed tuic identity")
        proxy = {
            "name": name,
            "type": "tuic",
            "server": server,
            "port": port,
            "uuid": identity,
            "password": password,
            "udp-relay-mode": _param(params, "udp_relay_mode", "udp-relay-mode") or "native",
            "congestion-controller": _param(
                params, "congestion_control", "congestion-controller"
            ) or "cubic",
        }
        sni = _param(params, "sni", "peer")
        if sni:
            proxy["sni"] = sni
        alpn = _param(params, "alpn")
        if alpn:
            proxy["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]
        if _param(params, "insecure", "allowinsecure", "allow_insecure").lower() in ("1", "true"):
            proxy["skip-cert-verify"] = True
        if _param(params, "reduce_rtt", "reduce-rtt").lower() in ("1", "true"):
            proxy["reduce-rtt"] = True
        return proxy

    raise UnsupportedNodeError(f"unsupported_protocol:{protocol}")


def build_mihomo_config(
    config: ParsedConfig,
    *,
    listen_port: int,
    resolved_ip: str | None = None,
    name: str = "proxy",
) -> dict:
    """Build the full Mihomo test config (mixed-port + MATCH,proxy rule)."""
    proxy = build_mihomo_proxy(config, resolved_ip=resolved_ip, name=name)
    return {
        "mixed-port": int(listen_port),
        "mode": "rule",
        "log-level": "error",
        "allow-lan": False,
        "unified-delay": true_false(True),
        "tcp-concurrent": true_false(False),
        "proxies": [proxy],
        "rules": ["MATCH,proxy"],
    }


def true_false(value: bool) -> bool:
    """Explicit bool helper (keeps YAML output deterministic)."""
    return bool(value)


def _apply_tls_mihomo(
    proxy: dict, config: ParsedConfig, protocol: str, *, force_tls: bool | None = None
) -> None:
    params = config.params
    security = _param(params, "security").lower()
    reality = security == "reality" or bool(_param(params, "pbk"))
    tls = force_tls if force_tls is not None else (
        protocol == "trojan" or security in ("tls", "reality")
    )
    if not tls and not reality:
        return
    proxy["tls"] = True
    sni = _param(params, "sni", "peer", "host")
    if not sni and config.host and not is_ip_literal(config.host):
        sni = config.host
    if sni:
        # Field name matters: mihomo's trojan client verifies the
        # certificate against ``sni`` (``servername`` is the vless/vmess
        # field). Verified against mihomo v1.19.31 with a real tunnel:
        # using ``servername`` on trojan makes Go verify against the raw
        # server IP ("no IP SANs") and the node wrongly fails.
        if protocol == "trojan":
            proxy["sni"] = sni
        else:
            proxy["servername"] = sni
    if _param(params, "insecure", "allowinsecure", "allow_insecure").lower() in ("1", "true"):
        proxy["skip-cert-verify"] = True
    alpn = _param(params, "alpn")
    if alpn:
        items = [item.strip() for item in alpn.split(",") if item.strip()]
        if items:
            proxy["alpn"] = items
    fingerprint = _param(params, "fp")
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint
    if reality:
        pbk = _param(params, "pbk")
        if not pbk:
            raise UnsupportedNodeError("unsupported_option:reality_without_pbk")
        reality_opts: dict = {"public-key": pbk}
        sid = _param(params, "sid")
        if sid:
            reality_opts["short-id"] = sid
        proxy["reality-opts"] = reality_opts


def _apply_network_mihomo(proxy: dict, config: ParsedConfig) -> None:
    params = config.params
    net = _param(params, "type", "net").lower() or "tcp"
    if net in ("tcp", "raw", "none", ""):
        return
    if net == "ws":
        proxy["network"] = "ws"
        ws: dict = {"path": _param(params, "path") or "/"}
        host = _param(params, "host")
        if host:
            ws["headers"] = {"Host": host}
        proxy["ws-opts"] = ws
        return
    if net == "grpc":
        proxy["network"] = "grpc"
        service = _param(params, "servicename", "service_name") or _param(params, "path")
        proxy["grpc-opts"] = {"grpc-service-name": service or ""}
        return
    if net in ("h2", "http"):
        proxy["network"] = "h2"
        h2: dict = {"path": _param(params, "path") or "/"}
        host = _param(params, "host")
        if host:
            h2["host"] = [host]
        proxy["h2-opts"] = {"host": h2.get("host", []), "path": h2["path"]}
        return
    if net == "httpupgrade":
        proxy["network"] = "httpupgrade"
        proxy["httpupgrade-opts"] = {
            "path": _param(params, "path") or "/",
            "host": _param(params, "host"),
        }
        return
    if net in ("xhttp", "splithttp"):
        if config.protocol != "vless":
            raise UnsupportedNodeError(f"unsupported_transport:{net}")
        proxy["network"] = "xhttp"
        opts: dict = {
            "path": _param(params, "path") or "/",
            "mode": _param(params, "mode") or "auto",
        }
        host = _param(params, "host")
        if host:
            opts["host"] = host
        proxy["xhttp-opts"] = opts
        return
    raise UnsupportedNodeError(f"unsupported_transport:{net}")


def _ss_plugin_opts(plugin_name: str, plugin_raw: str) -> dict:
    """Parse SIP003 plugin-opts from the URI plugin string."""
    opts: dict = {}
    parts = plugin_raw.split(";", 1)
    if len(parts) == 2:
        for pair in parts[1].split(";"):
            key, _, value = pair.partition("=")
            if not key:
                continue
            if plugin_name == "obfs" and key == "obfs":
                opts["mode"] = value
            elif plugin_name == "obfs" and key == "obfs-host":
                opts["host"] = value
            else:
                opts[key.replace("-", "_")] = value
    return opts
