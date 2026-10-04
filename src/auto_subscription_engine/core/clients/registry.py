"""Authoritative Stage-7 client/core capability registry.

The registry separates three different concepts that were previously mixed:

* **core** - the executable that is runtime-tested;
* **client** - the application family receiving a feed;
* **format** - the artifact emitted for that client.

A client is publishable only when this repository owns a native builder and a
runtime-verifiable core mapping for it.  Future clients are intentionally not
listed here until those two conditions are true; that prevents "support" from
being claimed merely because a URI happens to import.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CoreSpec:
    key: str
    protocols: frozenset[str]
    transports: dict[str, frozenset[str]] = field(default_factory=dict)
    ss_plugins: frozenset[str] = frozenset()

    def supports(self, protocol: str, transport: str = "tcp", *, plugin: str = "") -> bool:
        protocol = str(protocol or "").lower()
        transport = _transport_alias(str(transport or "tcp"))
        if protocol not in self.protocols:
            return False
        allowed = self.transports.get(protocol)
        if allowed is not None and transport not in allowed:
            return False
        if protocol == "ss" and plugin and plugin not in self.ss_plugins:
            return False
        return True


@dataclass(frozen=True)
class ClientSpec:
    key: str
    core: str
    artifact: str
    format: str
    runtime_verified: bool = True
    #: OS families that consume this client's feed ("android", "windows").
    platforms: frozenset[str] = frozenset()
    #: Device-level evidence boundary. The engine never claims a device
    #: test it did not run, so every registry client starts here.
    device_evidence: str = "device_validation_unknown"


_TCPISH = frozenset({"tcp", "ws", "grpc", "h2", "httpupgrade"})
_XRAY_VLESS = frozenset({*_TCPISH, "xhttp"})
_MIHOMO_VLESS = frozenset({*_TCPISH, "xhttp"})

CORES: dict[str, CoreSpec] = {
    "singbox": CoreSpec(
        key="singbox",
        protocols=frozenset({"vless", "vmess", "trojan", "ss", "hysteria2", "tuic"}),
        transports={
            "vless": _TCPISH,
            "vmess": _TCPISH,
            "trojan": _TCPISH,
            "ss": frozenset({"tcp"}),
            "hysteria2": frozenset({"quic", "udp", "tcp"}),
            "tuic": frozenset({"quic", "udp", "tcp"}),
        },
    ),
    "xray": CoreSpec(
        key="xray",
        protocols=frozenset({"vless", "vmess", "trojan", "ss"}),
        transports={
            "vless": _XRAY_VLESS,
            "vmess": _TCPISH,
            "trojan": _TCPISH,
            "ss": frozenset({"tcp"}),
        },
    ),
    "hiddify": CoreSpec(
        key="hiddify",
        protocols=frozenset({"vless", "vmess", "trojan", "ss", "hysteria2", "tuic"}),
        transports={
            "vless": _TCPISH,
            "vmess": _TCPISH,
            "trojan": _TCPISH,
            "ss": frozenset({"tcp"}),
            "hysteria2": frozenset({"quic", "udp", "tcp"}),
            "tuic": frozenset({"quic", "udp", "tcp"}),
        },
    ),
    "mihomo": CoreSpec(
        key="mihomo",
        protocols=frozenset({"vless", "vmess", "trojan", "ss", "hysteria2", "tuic"}),
        transports={
            "vless": _MIHOMO_VLESS,
            "vmess": _TCPISH,
            "trojan": _TCPISH,
            "ss": frozenset({"tcp"}),
            "hysteria2": frozenset({"quic", "udp", "tcp"}),
            "tuic": frozenset({"quic", "udp", "tcp"}),
        },
        ss_plugins=frozenset({"obfs", "v2ray-plugin"}),
    ),
}

CLIENTS: dict[str, ClientSpec] = {
    "v2rayng": ClientSpec(
        "v2rayng", "xray", "v2rayng.txt", "uri",
        platforms=frozenset({"android"}),
    ),
    "hiddify": ClientSpec(
        "hiddify", "hiddify", "hiddify.txt", "uri",
        platforms=frozenset({"android", "windows"}),
    ),
    "nekobox": ClientSpec(
        "nekobox", "singbox", "nekobox.txt", "uri",
        platforms=frozenset({"android", "windows"}),
    ),
    "singbox": ClientSpec(
        "singbox", "singbox", "singbox.json", "singbox-json",
        platforms=frozenset({"android", "windows"}),
    ),
    "mihomo": ClientSpec(
        "mihomo", "mihomo", "mihomo.yaml", "mihomo-yaml",
        platforms=frozenset({"android", "windows"}),
    ),
}

#: Platform families that receive mirrored feed trees under
#: ``platforms/<family>/``. Order is also the documentation order.
PLATFORM_FAMILIES: tuple[str, ...] = ("android", "windows")

#: Windows-only client aliases: the client imports an existing registry
#: client's artifact format (same serializer, same runtime-core evidence),
#: so it is served by mirroring that client's qualified set under
#: ``platforms/windows/``. Key = alias artifact, value = (source client
#: registry key, evidence status). No separate scoring entry exists — no
#: duplicated evidence is created.
WINDOWS_CLIENT_ALIASES: dict[str, tuple[str, str]] = {
    # v2rayN imports the v2rayNG-family URI feed; runtime evidence: Xray.
    "v2rayn.txt": ("v2rayng", "runtime_core_verified"),
}

# These names are intentionally *not* publishable yet.  Stage 7 records the
# boundary explicitly so future work cannot accidentally claim support without
# native serialization + runtime validation.
PLANNED_CLIENTS: frozenset[str] = frozenset(
    {"shadowrocket", "stash", "loon", "surge", "quantumultx"}
)


def core_spec(key: str) -> CoreSpec:
    try:
        return CORES[key]
    except KeyError as exc:
        raise KeyError(f"unknown core: {key}") from exc


def client_spec(key: str) -> ClientSpec:
    try:
        return CLIENTS[key]
    except KeyError as exc:
        raise KeyError(f"unverified client: {key}") from exc


def _transport_alias(value: str) -> str:
    value = value.lower().strip()
    aliases = {
        "": "tcp",
        "raw": "tcp",
        "none": "tcp",
        "http": "h2",
        "splithttp": "xhttp",
    }
    return aliases.get(value, value)
