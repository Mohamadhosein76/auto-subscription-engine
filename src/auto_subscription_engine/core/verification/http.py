"""Application-layer HTTPS/HTTP probes through a local HTTP CONNECT proxy."""
from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlsplit

from .models import ApplicationProbeResult
from .policy import VerificationTarget

_USER_AGENT = (
    "AutoSubscriptionEngine/0.5.0 "
    "(+https://github.com/Mohamadhosein76/auto-subscription-engine)"
)
_HEADER_BUF_LIMIT = 64 * 1024


def _read_head(sock: socket.socket) -> tuple[str, bytes]:
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > _HEADER_BUF_LIMIT:
            raise ConnectionError("HTTP header block too large")
    head, separator, rest = buffer.partition(b"\r\n\r\n")
    return head.decode("latin1", errors="replace"), (rest if separator else b"")


def _read_body(sock: socket.socket, initial: bytes, max_body_bytes: int) -> bytes:
    body = bytearray(initial[:max_body_bytes])
    while len(body) < max_body_bytes:
        try:
            chunk = sock.recv(min(4096, max_body_bytes - len(body)))
        except (socket.timeout, ssl.SSLError):
            break
        if not chunk:
            break
        body.extend(chunk)
    return bytes(body)


def fetch_through_proxy(
    proxy_host: str,
    proxy_port: int,
    target: VerificationTarget,
    *,
    timeout: float,
    round_index: int = 0,
    max_body_bytes: int = 65536,
) -> ApplicationProbeResult:
    result = ApplicationProbeResult(
        url=target.url,
        kind=target.kind,
        required=target.required,
        round_index=round_index,
    )
    started = time.perf_counter()
    parts = urlsplit(target.url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        result.failure_reason = "invalid_test_url"
        return result

    target_host = parts.hostname
    target_port = parts.port or (443 if parts.scheme == "https" else 80)
    target_path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    tunnel: socket.socket | None = None
    try:
        tunnel = socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout)
        tunnel.settimeout(timeout)
        tunnel.sendall(
            (
                f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n\r\n"
            ).encode("ascii")
        )
        connect_head, _ = _read_head(tunnel)
        try:
            connect_status = int(connect_head.split("\r\n", 1)[0].split()[1])
        except (IndexError, ValueError):
            result.failure_reason = "proxy_connect_failed"
            return result
        if not 200 <= connect_status < 300:
            result.failure_reason = "proxy_connect_failed"
            return result

        if parts.scheme == "https":
            context = ssl.create_default_context()
            tunnel = context.wrap_socket(tunnel, server_hostname=target_host)
            tunnel.settimeout(timeout)

        tunnel.sendall(
            (
                f"GET {target_path} HTTP/1.1\r\n"
                f"Host: {target_host}\r\n"
                f"User-Agent: {_USER_AGENT}\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
        )
        response_head, initial_body = _read_head(tunnel)
        try:
            status = int(response_head.split("\r\n", 1)[0].split()[1])
        except (IndexError, ValueError):
            result.failure_reason = "malformed_http_response"
            return result
        result.status = status
        result.latency_ms = (time.perf_counter() - started) * 1000.0
        if status not in target.expect_statuses:
            result.failure_reason = "unexpected_status"
            return result

        if target.expect_substring is not None:
            body = _read_body(tunnel, initial_body, max_body_bytes)
            needle = target.expect_substring.encode("utf-8")
            result.body_validated = needle in body
            if not result.body_validated:
                result.failure_reason = "content_mismatch"
                return result
        result.ok = True
        return result
    except socket.timeout:
        result.failure_reason = "http_timeout"
        return result
    except ssl.SSLError:
        result.failure_reason = "tls_error"
        return result
    except (ConnectionError, OSError):
        result.failure_reason = "network_error"
        return result
    except Exception as exc:
        result.failure_reason = f"internal_error:{type(exc).__name__}"
        return result
    finally:
        if tunnel is not None:
            try:
                tunnel.close()
            except OSError:
                pass
