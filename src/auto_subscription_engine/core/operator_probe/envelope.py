"""Cross-language HMAC envelope used by Python control plane and Go agents."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any


class EnvelopeError(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedEnvelope:
    kind: str
    key_id: str
    payload: dict[str, Any]
    payload_bytes: bytes


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _mac_input(version: int, kind: str, payload_b64: str) -> bytes:
    return f"{version}\n{kind}\n{payload_b64}".encode("ascii")


def sign_payload(payload: dict[str, Any], *, kind: str, key_id: str, secret: str) -> dict[str, Any]:
    if not secret:
        raise EnvelopeError("probe signing secret is empty")
    version = 1
    raw = canonical_json_bytes(payload)
    payload_b64 = base64.b64encode(raw).decode("ascii")
    signature = hmac.new(secret.encode("utf-8"), _mac_input(version, kind, payload_b64), hashlib.sha256).hexdigest()
    return {
        "version": version,
        "kind": kind,
        "key_id": key_id,
        "payload_b64": payload_b64,
        "signature": signature,
    }


def verify_envelope(envelope: dict[str, Any], *, expected_kind: str, secret: str) -> VerifiedEnvelope:
    try:
        version = int(envelope["version"])
        kind = str(envelope["kind"])
        key_id = str(envelope["key_id"])
        payload_b64 = str(envelope["payload_b64"])
        signature = str(envelope["signature"])
    except (KeyError, TypeError, ValueError) as exc:
        raise EnvelopeError("malformed envelope") from exc
    if version != 1 or kind != expected_kind:
        raise EnvelopeError("unexpected envelope version or kind")
    expected = hmac.new(secret.encode("utf-8"), _mac_input(version, kind, payload_b64), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise EnvelopeError("invalid envelope signature")
    try:
        raw = base64.b64decode(payload_b64, validate=True)
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError("invalid envelope payload") from exc
    if not isinstance(payload, dict):
        raise EnvelopeError("envelope payload must be an object")
    return VerifiedEnvelope(kind=kind, key_id=key_id, payload=payload, payload_bytes=raw)
