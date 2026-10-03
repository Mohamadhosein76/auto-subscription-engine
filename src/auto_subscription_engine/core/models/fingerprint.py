"""Canonical normalization and logical fingerprinting."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from .schema import ParsedConfig

if TYPE_CHECKING:
    from .schema import CanonicalProxy

_FINGERPRINT_PARAMS: dict[str, dict[str, str]] = {
    "vless": {
        "type": "tcp",
        "security": "none",
        "flow": "",
        "sni": "",
        "host": "",
        "path": "",
        "servicename": "",
        "alpn": "",
        "fp": "",
        "pbk": "",
        "sid": "",
        "spx": "",
    },
    "vmess": {
        "net": "tcp",
        "type": "none",
        "tls": "none",
        "sni": "",
        "host": "",
        "path": "",
        "alpn": "",
        "fp": "",
    },
    "trojan": {
        "type": "tcp",
        "security": "tls",
        "sni": "",
        "host": "",
        "path": "",
        "alpn": "",
        "fp": "",
        "pbk": "",
        "sid": "",
    },
    "ss": {"plugin": ""},
    "hysteria2": {
        "sni": "",
        "obfs": "",
        "obfs-password": "",
        "alpn": "",
        "pinsha256": "",
    },
    "tuic": {
        "password": "",
        "sni": "",
        "alpn": "",
        "congestion_control": "cubic",
        "udp_relay_mode": "native",
        "allow_insecure": "0",
        "insecure": "0",
    },
}

_CASE_INSENSITIVE_KEYS = frozenset(
    {
        "type",
        "security",
        "tls",
        "net",
        "flow",
        "sni",
        "host",
        "alpn",
        "obfs",
        "fp",
        "congestion_control",
        "udp_relay_mode",
    }
)
_SEP = "\x1f"


def normalize_config(config: ParsedConfig) -> ParsedConfig:
    """Normalize stable endpoint fields and attach a logical fingerprint."""
    if config.host:
        config.host = config.host.strip().lower().rstrip(".")
    if config.name is not None:
        config.name = config.name.strip() or None
    config.fingerprint = compute_fingerprint(config)
    return config


def compute_fingerprint(config: ParsedConfig) -> str:
    """Fingerprint one compatibility config by connection semantics."""
    parts = [
        f"protocol={config.protocol}",
        f"host={config.host or ''}",
        f"port={config.port if config.port is not None else ''}",
        f"identity={_canonical_identity(config)}",
    ]

    lowered = {key.lower(): value for key, value in config.params.items()}
    defaults = _FINGERPRINT_PARAMS.get(config.protocol, {})
    for key in sorted(defaults):
        value = _canonical_value(key, lowered.get(key, ""), defaults[key])
        parts.append(f"{key}={value}")

    canonical = _SEP.join(parts)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_canonical_fingerprint(config: "CanonicalProxy") -> str:
    """Fingerprint a canonical proxy independently of its source container."""
    from .convert import canonical_to_legacy

    return compute_fingerprint(canonical_to_legacy(config))


def _canonical_identity(config: ParsedConfig) -> str:
    identity = config.identity or ""
    if config.protocol in {"vless", "vmess", "tuic"}:
        return identity.strip().lower()
    if config.protocol == "ss":
        method, separator, password = identity.partition(":")
        if separator:
            return f"{method.strip().lower()}:{password}"
    return identity


def _canonical_value(key: str, value: str, default: str) -> str:
    value = str(value).strip()
    if key in {"security", "tls"}:
        value = value.lower()
        return value or default
    if key == "alpn":
        return _normalize_alpn(value)
    if key in {"allow_insecure", "insecure"}:
        return "1" if value.lower() in {"1", "true", "yes", "on"} else "0"
    if key in _CASE_INSENSITIVE_KEYS:
        value = value.lower()
    return value or default


def _normalize_alpn(value: str) -> str:
    items = (
        item.strip().lower()
        for item in value.split(",")
        if item.strip()
    )
    return ",".join(sorted(items))
