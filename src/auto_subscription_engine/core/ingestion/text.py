"""Plain/base64 subscription decoding and nested URL discovery."""

from __future__ import annotations

import re

from ..utils.base64 import robust_b64decode

_HTTP_RE = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)


def decode_subscription_text(raw: str) -> tuple[str, str]:
    """Return decoded text plus container encoding (``plain``/``base64``)."""
    text = raw.strip()
    if not text:
        return "", "plain"
    if "://" in text:
        return text, "plain"

    decoded = robust_b64decode(text)
    if decoded is not None:
        shape = decoded.lstrip()
        if (
            "://" in decoded
            or "\n" in decoded
            or shape.startswith(("{", "["))
            or "proxies:" in decoded
            or "proxy-providers:" in decoded
        ):
            return decoded, "base64"

    return text, "plain"


def extract_uri_lines(raw: str) -> list[str]:
    """Extract non-HTTP share-link lines from plain/base64 text."""
    text, _ = decode_subscription_text(raw)
    result: list[str] = []
    for line in text.splitlines():
        value = line.strip()
        if not value or "://" not in value:
            continue
        if value.lower().startswith(("http://", "https://")):
            continue
        result.append(value)
    return result


def extract_nested_urls(raw: str) -> list[str]:
    """Discover nested HTTP subscription URLs without fetching them."""
    text, _ = decode_subscription_text(raw)
    result: list[str] = []

    for line in text.splitlines():
        value = line.strip()
        if _HTTP_RE.match(value):
            result.append(value)
            continue

        if value.lower().startswith("hiddify://import/"):
            nested = value[len("hiddify://import/") :].split("#", 1)[0]
            if _HTTP_RE.match(nested):
                result.append(nested)

    return list(dict.fromkeys(result))
