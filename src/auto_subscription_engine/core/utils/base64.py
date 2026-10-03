"""Robust Base64 decoding for subscription and protocol payloads."""

from __future__ import annotations

import base64
import binascii

_URLSAFE_TO_STANDARD = str.maketrans("-_", "+/")


def robust_b64decode(data: str) -> str | None:
    """Decode standard or URL-safe Base64 without raising on bad input."""
    compact = "".join(data.split())
    if not compact:
        return None

    candidates = (compact, compact.translate(_URLSAFE_TO_STANDARD))
    for candidate in candidates:
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue

        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            continue

    return None
