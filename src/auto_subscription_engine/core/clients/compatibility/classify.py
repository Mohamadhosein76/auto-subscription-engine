"""Network resilience classification and conservative feed policy.

Classifies every node on operator-relevant, *measured* properties only
(IP version, transport, port, TLS/Reality, direct-IP vs hostname). The
classification feeds the ``network_profile`` metadata, the dedicated
network feeds (tcp/udp/ipv4/ipv6/port443) and the conservative
``mobile-safe`` candidate feed.

Honesty rules (spec item 19):

- nothing here claims operator reachability; GitHub runners cannot test
  Iranian/other ISPs. Everything is documented as ``mobile-safe
  candidate`` / ``operator-resilient`` heuristics, never guarantees;
- UDP-only protocols (Hysteria2) never dominate the mobile feed: TCP
  TLS-443 nodes are ranked first and the UDP share is capped whenever
  real TCP alternatives exist.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...models import ParsedConfig
from ...network import ip_version, is_ip_literal
from .audit import node_features
from .matrix import UDP_PROTOCOLS


@dataclass
class NetworkProfile:
    """Credential-free network properties of one node."""

    ipv4: bool = False
    ipv6: bool = False
    tcp: bool = True
    udp: bool = False
    port: int | None = None
    port_443: bool = False
    tls: bool = False
    reality: bool = False
    websocket: bool = False
    grpc: bool = False
    direct_ip: bool = False
    hostname: bool = False
    udp_dependency: bool = False

    def to_dict(self) -> dict:
        return {
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "tcp": self.tcp,
            "udp": self.udp,
            "port": self.port,
            "port_443": self.port_443,
            "tls": self.tls,
            "reality": self.reality,
            "websocket": self.websocket,
            "grpc": self.grpc,
            "direct_ip": self.direct_ip,
            "hostname": self.hostname,
            "udp_dependency": self.udp_dependency,
        }


def classify_network(config: ParsedConfig, resolved_ip: str | None = None) -> NetworkProfile:
    """Deterministic network-profile classification for one node."""
    features = node_features(config)
    profile = NetworkProfile()
    profile.port = int(config.port) if config.port else None
    profile.port_443 = profile.port == 443

    host = config.host or ""
    effective_ip = resolved_ip or (host if is_ip_literal(host) else "")
    if effective_ip:
        version = ip_version(effective_ip)
        profile.ipv4 = version == 4
        profile.ipv6 = version == 6
    profile.direct_ip = bool(effective_ip)
    profile.hostname = bool(host) and not is_ip_literal(host)

    profile.udp_dependency = features.protocol in UDP_PROTOCOLS
    profile.tcp = not profile.udp_dependency
    profile.udp = profile.udp_dependency

    profile.tls = features.tls
    profile.reality = features.reality
    profile.websocket = features.websocket
    profile.grpc = features.grpc
    return profile



# ---------------------------------------------------------------------------
# Feed policies
# ---------------------------------------------------------------------------


def network_feed_membership(profile: NetworkProfile) -> dict[str, bool]:
    """Which network feeds this node belongs to (port443/tcp/udp/...)."""
    return {
        "tcp": profile.tcp,
        "udp": profile.udp,
        "ipv4": profile.ipv4,
        "ipv6": profile.ipv6,
        "port443": profile.port_443,
    }


def mobile_safe_rank(
    profile: NetworkProfile,
    *,
    protocol: str,
    cores_passed_fraction: float,
    proxy_latency_ms: float | None,
    rolling_success_rate: float | None,
    max_latency_ms: float,
) -> tuple[int, ...]:
    """Conservative mobile/restricted-network ordering key (lower = better).

    Preference (spec item 17): TCP-based first, TLS/Reality/443 next,
    good tunnel latency, multi-core agreement, low historical failure.
    Hysteria2/UDP-dependent nodes are ranked strictly after any TCP node
    so they can never dominate the feed.
    """
    latency = proxy_latency_ms if proxy_latency_ms is not None else float("inf")
    history_ok = rolling_success_rate is None or rolling_success_rate >= 0.5
    groups = (
        0 if profile.tcp else 1,                     # TCP before UDP-only
        0 if (profile.tls or profile.reality) else 1,
        0 if profile.port_443 else 1,
        0 if history_ok else 1,
    )
    float_key = (
        latency if latency <= max_latency_ms else max_latency_ms + (latency - max_latency_ms),
        -cores_passed_fraction,
    )
    # Group first as ints; latency as a deterministic tiebreak component.
    return groups + (round(float_key[0] * 1000), round(float_key[1] * 1_000_000), 0 if protocol else 0)
