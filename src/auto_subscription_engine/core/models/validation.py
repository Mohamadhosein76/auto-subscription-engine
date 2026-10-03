"""Structural validation for compatibility and canonical ingestion."""

from __future__ import annotations

from dataclasses import dataclass

from ..network import is_local_host, is_valid_host_format
from .schema import ParsedConfig, SUPPORTED_PROTOCOLS


@dataclass(frozen=True)
class ValidationResult:
    """Result of structural validation for one compatibility config."""

    ok: bool
    reason: str | None = None


def validate_config(config: ParsedConfig) -> ValidationResult:
    reason = _first_problem(config)
    return ValidationResult(ok=reason is None, reason=reason)


def _first_problem(config: ParsedConfig) -> str | None:
    if config.protocol not in SUPPORTED_PROTOCOLS:
        return f"unsupported protocol: {config.protocol}"

    host = (config.host or "").strip()
    if not host:
        return "missing host"
    if not is_valid_host_format(host):
        return "invalid host format"
    if is_local_host(host):
        return "local or private host"

    if config.port is None:
        return "missing port"
    if not 1 <= config.port <= 65535:
        return "port out of range"

    return _identity_problem(config)


def _identity_problem(config: ParsedConfig) -> str | None:
    identity = (config.identity or "").strip()

    if config.protocol in {"vless", "vmess"}:
        if not identity:
            return "missing user id"
    elif config.protocol in {"trojan", "hysteria2"}:
        if not identity:
            return "missing password"
    elif config.protocol == "ss":
        if not identity:
            return "missing method and password"
        method, separator, password = identity.partition(":")
        if not separator or not method or not password:
            return "missing method or password"
    elif config.protocol == "tuic":
        if not identity:
            return "missing user id"
        if not str(config.params.get("password", "")).strip():
            return "missing password"

    return None
