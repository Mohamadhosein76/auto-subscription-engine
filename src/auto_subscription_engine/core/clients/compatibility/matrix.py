"""Capability matrix derived from the Stage-7 central client registry."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..registry import CORES as CORE_REGISTRY, core_spec

CORE_KEYS = tuple(CORE_REGISTRY)
# Backward-friendly name used by scoring; now registry-derived.
CORES = CORE_KEYS
PROTOCOL_SUPPORT: dict[str, frozenset[str]] = {
    key: spec.protocols for key, spec in CORE_REGISTRY.items()
}
TCP_TRANSPORTS = frozenset({"tcp", "raw", "ws", "grpc", "h2", "http", "httpupgrade", "xhttp"})
UDP_PROTOCOLS = frozenset({"hysteria2", "tuic"})
SS_PLUGINS_SUPPORTED = {
    key: spec.ss_plugins for key, spec in CORE_REGISTRY.items() if spec.ss_plugins
}


@dataclass(frozen=True)
class Capability:
    supported: bool
    detail: str = ""


@dataclass
class NodeFeatures:
    protocol: str
    transport: str = "tcp"
    tls: bool = False
    reality: bool = False
    websocket: bool = False
    grpc: bool = False
    http_upgrade: bool = False
    flow: str = ""
    plugin: str = ""
    extras: frozenset[str] = field(default_factory=frozenset)


def protocol_supported(core: str, protocol: str) -> bool:
    spec = CORE_REGISTRY.get(core)
    return bool(spec and protocol in spec.protocols)


def protocol_portability(protocol: str) -> float:
    if not CORE_KEYS:
        return 0.0
    return sum(1 for core in CORE_KEYS if protocol_supported(core, protocol)) / len(CORE_KEYS)


def protocol_common(protocol: str) -> bool:
    return all(protocol_supported(core, protocol) for core in CORE_KEYS)


def capabilities_for(features: NodeFeatures) -> dict[str, Capability]:
    result: dict[str, Capability] = {}
    for core in CORE_KEYS:
        spec = core_spec(core)
        if features.protocol not in spec.protocols:
            result[core] = Capability(False, f"unsupported_protocol:{features.protocol}")
            continue
        # Preserve a specific reason for transport/plugin refusal so diagnostics
        # remain useful instead of collapsing everything into a generic false.
        if not spec.supports(features.protocol, features.transport, plugin=features.plugin):
            if features.protocol == "ss" and features.plugin and features.plugin not in spec.ss_plugins:
                result[core] = Capability(False, f"unsupported_option:ss_plugin:{features.plugin}")
            else:
                result[core] = Capability(False, f"unsupported_transport:{features.transport}")
            continue
        result[core] = Capability(True)
    return result


def universal_eligible(features: NodeFeatures) -> bool:
    caps = capabilities_for(features)
    return bool(caps) and all(cap.supported for cap in caps.values())
