"""Safe, non-sensitive node identifiers for logs and public metadata.

A node is never referenced by its URI, UUID, password or display name in
logs. Instead every config gets a deterministic *safe id* derived by
double-hashing its logical fingerprint, e.g. ``node_ab12cd34ef56``.

The fingerprint itself is already a SHA-256 digest of the endpoint, so
the safe id reveals nothing about credentials while remaining stable
across runs (required for reliability history).
"""

from __future__ import annotations

import hashlib

from ..models import ParsedConfig

_SAFE_ID_PREFIX = "node_"
_SAFE_ID_HEX_CHARS = 12


def safe_id(fingerprint: str) -> str:
    """Return a stable, credential-free identifier for a fingerprint."""
    digest = hashlib.sha256((fingerprint or "").encode("utf-8")).hexdigest()
    return _SAFE_ID_PREFIX + digest[:_SAFE_ID_HEX_CHARS]


def config_safe_id(config: ParsedConfig) -> str:
    """Return the safe id of a parsed config."""
    return safe_id(config.fingerprint or compute_fallback(config))


def compute_fallback(config: ParsedConfig) -> str:
    """Best-effort fingerprint substitute for configs that were not normalized."""
    return "|".join(
        (
            config.protocol,
            config.host or "",
            str(config.port or 0),
            config.identity or "",
        )
    )


def describe_node(config: ParsedConfig) -> str:
    """One-line, credential-free node description for logs."""
    return (
        f"{config.protocol} {config_safe_id(config)} "
        f"endpoint={config.host or '?'}:{config.port or '?'}"
    )
