"""Bounded HTTP fetcher used only by the discovery subsystem."""
from __future__ import annotations

import time

import requests

from .models import FetchOutcome, SourceDefinition

USER_AGENT = "AutoSubscriptionEngine/0.2 (+https://github.com/Mohamadhosein76/auto-subscription-engine)"
DEFAULT_TIMEOUT = 15.0
DEFAULT_RETRIES = 2
DEFAULT_MAX_BYTES = 16 * 1024 * 1024
_RETRYABLE = frozenset({429, 500, 502, 503, 504})


def fetch_source(
    source: SourceDefinition,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backoff: float = 0.5,
    session: requests.Session | None = None,
) -> FetchOutcome:
    session = session or requests.Session()
    result = FetchOutcome(source=source)
    attempts = max(0, retries) + 1
    started = time.monotonic()
    for attempt in range(1, attempts + 1):
        try:
            response = session.get(
                source.url,
                headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
                timeout=timeout,
                stream=True,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            result = FetchOutcome(
                source=source,
                error=_describe_exception(exc),
                elapsed_ms=(time.monotonic() - started) * 1000,
            )
        else:
            try:
                status = int(response.status_code)
                if status == 200:
                    body = _read_body(response, max_bytes)
                    if body is None:
                        return FetchOutcome(
                            source=source,
                            status_code=status,
                            error=f"response exceeds {max_bytes} bytes",
                            elapsed_ms=(time.monotonic() - started) * 1000,
                        )
                    return FetchOutcome(
                        source=source,
                        ok=True,
                        status_code=status,
                        content=_decode_body(response, body),
                        byte_count=len(body),
                        elapsed_ms=(time.monotonic() - started) * 1000,
                    )
                result = FetchOutcome(
                    source=source,
                    status_code=status,
                    error=f"HTTP {status}",
                    elapsed_ms=(time.monotonic() - started) * 1000,
                )
                if status not in _RETRYABLE:
                    return result
            finally:
                response.close()
        if attempt < attempts and backoff > 0:
            time.sleep(backoff)
    return result


def _read_body(response: requests.Response, max_bytes: int) -> bytes | None:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _decode_body(response: requests.Response, data: bytes) -> str:
    encoding = response.encoding
    if not encoding or encoding.lower() == "iso-8859-1":
        return data.decode("utf-8", errors="replace")
    try:
        return data.decode(encoding, errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def _describe_exception(exc: Exception) -> str:
    message = str(exc)
    if len(message) > 200:
        message = message[:197] + "..."
    return f"{type(exc).__name__}: {message}"
