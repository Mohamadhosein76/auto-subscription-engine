"""Log redaction helpers (Task 2 security requirement).

Nothing that appears in engine logs or diagnostics may contain:

- full UUIDs
- passwords / encryption secrets / auth tokens
- full proxy URIs
- long key-like blobs

All log lines about nodes are built through :func:`redact_text`, and the
per-node logger :func:`node_log` always uses the safe id from
:mod:`auto_subscription_engine.core.utils.identity`.
"""

from __future__ import annotations

import re

#: Standard UUID shape (VLESS/VMess user ids).
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

#: Key/credential assignments such as ``password=...``, ``uuid: ...``.
_KV_SECRET_RE = re.compile(
    r"\b(password|passwd|pass|uuid|auth|token|secret|key|method|id)\b\s*[:=]\s*(\S+)",
    re.IGNORECASE,
)

#: URI userinfo (credentials embedded in a URL-ish string).
_URI_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^@\s/]+)@", re.IGNORECASE)

#: Long base64/hex-ish blobs (>= 24 chars) that look like keys.
_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/_=-]{24,}\b")

_REDACTED = "[REDACTED]"

_MAX_STDERR_CHARS = 400


def redact_text(text: str) -> str:
    """Return ``text`` with every credential-shaped value replaced."""
    result = _UUID_RE.sub(_REDACTED, text)
    result = _URI_USERINFO_RE.sub(r"\1" + _REDACTED + "@", result)
    result = _KV_SECRET_RE.sub(lambda m: f"{m.group(1)}={_REDACTED}", result)
    result = _BLOB_RE.sub(_REDACTED, result)
    return result


def redact_stderr(data: bytes | str, limit: int = _MAX_STDERR_CHARS) -> str:
    """Decode, truncate and redact a child process stderr snippet."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    snippet = data.strip()[:limit]
    return redact_text(snippet)


def node_log(logger, level: int, config, message: str) -> None:
    """Log about a node using only its safe id and redacted text."""
    from .identity import describe_node  # local import avoids a cycle

    logger.log(level, "%s: %s", describe_node(config), redact_text(message))
