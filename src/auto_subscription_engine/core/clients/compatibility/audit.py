"""Parser fidelity audit (multi-core layer, spec item 3/27/28).

For every parsed URI the audit answers one question: *is every field the
parser saw either mapped faithfully by a core builder or explicitly
declared unsupported?* A feature that cannot be represented faithfully
produces ``parser_feature_unsupported`` metadata and that feature is
refused by the builders (``unsupported_option``) — a fake PASS is never
recorded for a config whose semantics would silently change.
"""

from __future__ import annotations

from ...models import ParsedConfig
from .matrix import NodeFeatures

#: URI ``type``/``net`` values mapped to a canonical transport name.
_TRANSPORT_ALIASES = {
    "tcp": "tcp",
    "raw": "tcp",
    "none": "tcp",
    "": "tcp",
    "ws": "ws",
    "grpc": "grpc",
    "h2": "h2",
    "http": "h2",
    "httpupgrade": "httpupgrade",
    "xhttp": "xhttp",
    "splithttp": "xhttp",
}

#: Features the engine understands per protocol (everything else that
#: shows up in params/extra_fields is flagged).
_KNOWN_PARAMS: dict[str, frozenset[str]] = {
    "vless": frozenset({
        "type", "security", "flow", "sni", "host", "path", "servicename",
        "service_name", "alpn", "fp", "pbk", "sid", "spx", "encryption",
        "headerType", "allowInsecure", "insecure", "allow_insecure",
    }),
    "vmess": frozenset({"aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp"}),
    "trojan": frozenset({
        "type", "security", "sni", "host", "path", "alpn", "fp", "pbk",
        "sid", "spx", "allowInsecure", "insecure", "allow_insecure",
        "servicename", "service_name", "encryption",
    }),
    "ss": frozenset({"plugin", "plugin-opts"}),
    "hysteria2": frozenset({
        "sni", "obfs", "obfs-password", "obfsparam", "alpn", "pinsha256",
        "insecure", "allowinsecure", "allowInsecure",
    }),
    "tuic": frozenset({
        "password", "sni", "alpn", "congestion_control", "congestion-controller",
        "udp_relay_mode", "udp-relay-mode", "reduce_rtt", "reduce-rtt",
        "insecure", "allowinsecure", "allowInsecure",
    }),
}

#: Param keys whose presence marks a feature the builders refuse.
_REFUSED_OPTIONS = {
    "headerType": "headerType",
}

#: VMess legacy JSON obfuscation field (websocket early-data / obfs).
_EXTRA_FIELD_FLAGS = {
    "obfs": "vmess_obfs_json",
    "obfsParam": "vmess_obfsParam_json",
    "verify": "vmess_verify_json",
}


def node_features(config: ParsedConfig) -> NodeFeatures:
    """Extract the transport/security feature set from a parsed config."""
    params = {key.lower(): value for key, value in config.params.items()}
    protocol = config.protocol
    transport_raw = ""
    if protocol in ("vless", "trojan"):
        transport_raw = params.get("type", "tcp")
    elif protocol == "vmess":
        transport_raw = params.get("net", "tcp")
    elif protocol in ("hysteria2", "tuic"):
        transport_raw = "quic"
    transport = _TRANSPORT_ALIASES.get(transport_raw.strip().lower(), transport_raw.strip().lower() or "tcp")
    security = params.get("security", "")
    tls = (
        protocol == "trojan"
        or (protocol in ("vless", "vmess") and security in ("tls", "reality"))
        or (protocol == "vmess" and params.get("tls", "").lower() == "tls")
        or (protocol in ("hysteria2", "tuic"))
    )
    reality = security == "reality" or bool(params.get("pbk"))
    flow = params.get("flow", "")
    plugin_raw = params.get("plugin", "")
    plugin = plugin_raw.split(";", 1)[0].strip().lower() if plugin_raw else ""
    return NodeFeatures(
        protocol=protocol,
        transport=transport,
        tls=tls,
        reality=reality,
        websocket=transport == "ws",
        grpc=transport == "grpc",
        http_upgrade=transport == "httpupgrade",
        flow=flow,
        plugin=plugin,
    )


def unmapped_features(config: ParsedConfig) -> list[str]:
    """Deterministic list of ``parser_feature_unsupported`` codes.

    Covers:

    - URI params present but not in the engine's understood set;
    - VMess JSON fields preserved in ``extra_fields`` (never dropped);
    - headerType-style options the builders refuse to reinterpret;
    - Shadowsocks plugin families the live cores cannot run.
    """
    known = _KNOWN_PARAMS.get(config.protocol, frozenset())
    lowered_known = {key.lower() for key in known}
    flags: set[str] = set()

    for key in config.params:
        if key.lower() not in lowered_known:
            flags.add(f"param:{key}")

    for key in config.extra_fields:
        flag = _EXTRA_FIELD_FLAGS.get(key)
        if flag:
            flags.add(flag)
        else:
            flags.add(f"vmess_json:{key}")

    header_type = config.params.get("headerType")
    if header_type:
        flags.add(f"refused:headerType:{header_type}")

    features = node_features(config)
    if features.plugin and config.protocol == "ss":
        flags.add(f"ss_plugin:{features.plugin}")

    if features.flow and features.flow != "xtls-rprx-vision":
        flags.add(f"refused:flow:{features.flow}")


    return sorted(flags)
