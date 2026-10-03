"""Data models for address discovery and direct-IP candidate generation."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import CanonicalProxy
from .dns import ResolverAnswer


@dataclass(frozen=True)
class HostResolution:
    host: str
    answers: tuple[ResolverAnswer, ...] = ()

    @property
    def current_public_ips(self) -> tuple[str, ...]:
        values: set[str] = set()
        for answer in self.answers:
            values.update(answer.public_addresses)
        return tuple(sorted(values, key=_ip_key))

    @property
    def resolver_names(self) -> tuple[str, ...]:
        return tuple(answer.resolver for answer in self.answers)


@dataclass
class IpHunterResult:
    variants: list[CanonicalProxy] = field(default_factory=list)
    resolutions: dict[str, HostResolution] = field(default_factory=dict)
    direct_inputs: int = 0
    host_inputs: int = 0
    unresolved_hosts: int = 0
    current_variants: int = 0
    history_variants: int = 0
    skipped_non_public: int = 0
    truncated_variants: int = 0

    def to_stats(self) -> dict[str, int]:
        return {
            "direct_inputs": self.direct_inputs,
            "hostname_inputs": self.host_inputs,
            "hosts_resolved": sum(
                1 for item in self.resolutions.values() if item.current_public_ips
            ),
            "hosts_unresolved": self.unresolved_hosts,
            "variants_created": len(self.variants),
            "current_dns_variants": self.current_variants,
            "history_variants": self.history_variants,
            "non_public_addresses_skipped": self.skipped_non_public,
            "variants_truncated": self.truncated_variants,
        }


def _ip_key(value: str) -> tuple[int, int]:
    import ipaddress

    parsed = ipaddress.ip_address(value)
    return (parsed.version, int(parsed))
