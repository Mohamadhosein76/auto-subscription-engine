"""Canonical and compatibility data models for proxy configurations."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

CANONICAL_PROTOCOLS: frozenset[str] = frozenset(
    {"vless", "vmess", "trojan", "ss", "hysteria2", "tuic"}
)
# Protocols currently allowed into the legacy live pipeline. TUIC is parsed in
# Stage 2 but intentionally gated until its runtime client adapters land.
SUPPORTED_PROTOCOLS: frozenset[str] = frozenset(
    {"vless", "vmess", "trojan", "ss", "hysteria2", "tuic"}
)
SCHEME_ALIASES: dict[str, str] = {"hy2": "hysteria2"}


class ParseError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class UnknownProtocolError(ParseError):
    def __init__(self, scheme: str) -> None:
        super().__init__(f"unsupported scheme: {scheme}")
        self.scheme = scheme


class SourceConfigError(Exception):
    """Raised when source configuration is missing or invalid."""


class OriginFormat(StrEnum):
    URI = "uri"
    URI_LIST = "uri_list"
    BASE64_SUBSCRIPTION = "base64_subscription"
    CLASH_YAML = "clash_yaml"
    SINGBOX_JSON = "singbox_json"
    XRAY_JSON = "xray_json"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Endpoint:
    host: str | None = None
    port: int | None = None


@dataclass
class Authentication:
    """Protocol authentication fields without forcing them into one string."""
    kind: str = "none"
    values: dict[str, str] = field(default_factory=dict)

    def get(self, key: str, default: str = "") -> str:
        return self.values.get(key, default)


@dataclass
class TransportSpec:
    kind: str = "tcp"
    path: str = ""
    host: str = ""
    service_name: str = ""
    header_type: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class TlsSpec:
    enabled: bool = False
    mode: str = "none"
    server_name: str = ""
    alpn: tuple[str, ...] = ()
    fingerprint: str = ""
    insecure: bool = False
    reality_public_key: str = ""
    reality_short_id: str = ""
    reality_spider_x: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class CanonicalProxy:
    """Protocol-neutral source of truth used by ingestion and future stages."""
    protocol: str
    endpoint: Endpoint = field(default_factory=Endpoint)
    auth: Authentication = field(default_factory=Authentication)
    transport: TransportSpec = field(default_factory=TransportSpec)
    tls: TlsSpec = field(default_factory=TlsSpec)
    name: str | None = None
    options: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    origin_format: OriginFormat = OriginFormat.UNKNOWN
    raw: str = ""
    extra_fields: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""

    @property
    def host(self) -> str | None:
        return self.endpoint.host

    @property
    def port(self) -> int | None:
        return self.endpoint.port


@dataclass
class ParsedConfig:
    """Stable compatibility model consumed by the existing pipeline."""
    protocol: str
    host: str | None = None
    port: int | None = None
    identity: str | None = None
    name: str | None = None
    params: dict[str, str] = field(default_factory=dict)
    original_uri: str = ""
    fingerprint: str = ""
    source: str = ""
    extra_fields: dict[str, str] = field(default_factory=dict)
