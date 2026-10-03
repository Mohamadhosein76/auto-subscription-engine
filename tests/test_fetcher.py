"""Tests for the HTTP fetcher (all network interaction is faked)."""

from __future__ import annotations

import requests

from auto_subscription_engine.core.discovery.fetch import USER_AGENT, fetch_source
from auto_subscription_engine.core.discovery import SourceDefinition

SRC = SourceDefinition(name="test-source", url="https://sub.example.com/list.txt", source_id="test-source")


class FakeResponse:
    def __init__(self, status_code: int = 200, body: bytes = b"", encoding: str | None = None):
        self.status_code = status_code
        self.encoding = encoding
        self._chunks = [body[i : i + 64] for i in range(0, len(body), 64)] or [b""]
        self.closed = False

    def iter_content(self, chunk_size: int | None = None):
        return iter(self._chunks)

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, items: list):
        self.items = list(items)
        self.calls: list[tuple[str, dict]] = []

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_success() -> None:
    session = FakeSession([FakeResponse(200, b"vless://u@h.example.com:443#n\n")])
    result = fetch_source(SRC, session=session, timeout=10.0, backoff=0)
    assert result.ok
    assert result.status_code == 200
    assert result.content == "vless://u@h.example.com:443#n\n"
    assert result.error is None
    assert result.byte_count == len(b"vless://u@h.example.com:443#n\n")

    assert len(session.calls) == 1
    url, kwargs = session.calls[0]
    assert url == SRC.url
    assert kwargs["headers"]["User-Agent"] == USER_AGENT
    assert kwargs["timeout"] == 10.0
    assert kwargs["stream"] is True


def test_client_error_fails_without_retry() -> None:
    session = FakeSession([FakeResponse(404)])
    result = fetch_source(SRC, session=session, retries=2, backoff=0)
    assert not result.ok
    assert result.status_code == 404
    assert result.error == "HTTP 404"
    assert len(session.calls) == 1


def test_server_error_retried_until_success() -> None:
    session = FakeSession(
        [FakeResponse(500), FakeResponse(503), FakeResponse(200, b"data")]
    )
    result = fetch_source(SRC, session=session, retries=2, backoff=0)
    assert result.ok
    assert result.content == "data"
    assert len(session.calls) == 3


def test_server_error_retries_exhausted() -> None:
    session = FakeSession([FakeResponse(500), FakeResponse(500), FakeResponse(500)])
    result = fetch_source(SRC, session=session, retries=2, backoff=0)
    assert not result.ok
    assert result.error == "HTTP 500"
    assert len(session.calls) == 3


def test_network_error_then_success() -> None:
    session = FakeSession(
        [requests.exceptions.ConnectTimeout("boom"), FakeResponse(200, b"ok")]
    )
    result = fetch_source(SRC, session=session, retries=1, backoff=0)
    assert result.ok
    assert result.content == "ok"
    assert len(session.calls) == 2


def test_all_network_errors_fail() -> None:
    session = FakeSession(
        [
            requests.exceptions.ConnectionError("nope"),
            requests.exceptions.ConnectionError("nope"),
            requests.exceptions.ConnectionError("nope"),
        ]
    )
    result = fetch_source(SRC, session=session, retries=2, backoff=0)
    assert not result.ok
    assert result.error is not None
    assert result.error.startswith("ConnectionError")
    assert len(session.calls) == 3


def test_response_is_closed() -> None:
    response = FakeResponse(200, b"x")
    session = FakeSession([response])
    fetch_source(SRC, session=session, backoff=0)
    assert response.closed


def test_oversized_response_fails() -> None:
    session = FakeSession([FakeResponse(200, b"a" * 100)])
    result = fetch_source(SRC, session=session, max_bytes=50, backoff=0)
    assert not result.ok
    assert result.error is not None
    assert "exceeds" in result.error


def test_utf8_body_decoded() -> None:
    body = "vless://u@h.example.com:443#نام\n".encode("utf-8")
    session = FakeSession([FakeResponse(200, body)])
    result = fetch_source(SRC, session=session, backoff=0)
    assert result.content == "vless://u@h.example.com:443#نام\n"


def test_iso_latin1_fallback_decodes_as_utf8() -> None:
    # requests defaults to ISO-8859-1 when no charset is declared.
    body = "vless://u@h.example.com:443#name\n".encode("utf-8")
    session = FakeSession([FakeResponse(200, body, encoding="ISO-8859-1")])
    result = fetch_source(SRC, session=session, backoff=0)
    assert result.content == "vless://u@h.example.com:443#name\n"


def test_user_agent_is_specific() -> None:
    assert "AutoSubscriptionEngine" in USER_AGENT
