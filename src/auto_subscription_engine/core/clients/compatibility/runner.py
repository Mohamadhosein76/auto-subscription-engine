"""Per-core runtime tester: real process, real tunnel, real HTTPS.

For one node and one core the tester:

1. asks the core-specific builder for a config (builder refusals are
   recorded as ``unsupported_*`` — never as network failures);
2. writes the config to a 0600 file inside a 0700 temp dir
   (credentials never appear in process arguments);
3. spawns the real core binary and waits (bounded) for the local proxy
   port to accept connections;
4. pushes at least two independent HTTPS requests through the tunnel
   with full certificate verification; at least one destination is
   body-validated (content integrity);
5. kills the process and removes the temp directory on every path.

PASS requires: config accepted, core started, tunnel up, and at least
one fully-validated HTTPS response. An accepted config alone is never a
PASS (spec items 4-6).
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ...models import ParsedConfig
from ..runtime import CoreRuntimeManager, RuntimeCoreError
from ...version import HTTP_USER_AGENT

logger = logging.getLogger(__name__)

_USER_AGENT = HTTP_USER_AGENT
_HEADER_BUF_LIMIT = 64 * 1024

#: stderr markers that indicate the CONFIG was rejected (vs. a runtime
#: startup crash). Matched case-insensitively, bounded set.
_CONFIG_REJECTED_MARKERS = (
    "unmarshal",
    "invalid character",
    "parse error",
    "yaml:",
    "configuration file",
    "config error",
    "decoding failed",
    "syntax error",
    "not found in config",
    "missing field",
    "unknown field",
)


@dataclass(frozen=True)
class CompatTestUrl:
    """One egress probe for a compatibility run."""

    url: str
    expect_statuses: tuple[int, ...] = (200, 204)
    expect_substring: str | None = None  # body validation when set


@dataclass
class CoreTestResult:
    """Outcome of one node-on-one-core test (credential-free)."""

    core: str
    status: str = "fail"  # pass | fail | unsupported | unavailable
    failure_category: str | None = None
    latency_ms: float | None = None
    core_version: str | None = None
    probes: list[dict] = field(default_factory=list)
    detail: str = ""


def fetch_via_local_proxy(
    proxy_host: str,
    proxy_port: int,
    url: str,
    *,
    timeout: float,
    expect_statuses: Sequence[int],
    expect_substring: str | None = None,
    max_body_bytes: int = 65536,
) -> tuple[bool, int | None, float | None, str | None]:
    """One HTTPS request through the local proxy with optional body check.

    TLS verification is always on (``ssl.create_default_context``);
    ``verify=False`` equivalents are forbidden by project policy.
    Returns ``(ok, status, latency_ms, failure_reason)``.
    """
    from urllib.parse import urlsplit

    started = time.perf_counter()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False, None, None, "invalid_test_url"
    target_host = parts.hostname
    target_port = parts.port or (443 if parts.scheme == "https" else 80)
    target_path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    https = parts.scheme == "https"

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
        head = _read_head(tunnel)
        try:
            connect_status = int(head.split("\r\n", 1)[0].split()[1])
        except (IndexError, ValueError):
            return False, None, None, "proxy_connect_failed"
        if not 200 <= connect_status < 300:
            return False, None, None, "proxy_connect_failed"

        if https:
            context = ssl.create_default_context()
            tunnel = context.wrap_socket(tunnel, server_hostname=target_host)
            tunnel.settimeout(timeout)

        tunnel.sendall(
            (
                f"GET {target_path} HTTP/1.1\r\n"
                f"Host: {target_host}\r\n"
                f"User-Agent: {_USER_AGENT}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
        )
        head = _read_head(tunnel)
        status = int(head.split("\r\n", 1)[0].split()[1])
        latency = (time.perf_counter() - started) * 1000.0
        if status not in tuple(expect_statuses):
            return False, status, latency, "unexpected_status"
        if expect_substring is not None:
            body = tunnel.recv(max_body_bytes)
            if expect_substring.encode("utf-8") not in body:
                return False, status, latency, "content_integrity_failure"
        return True, status, latency, None
    except socket.timeout:
        return False, None, None, "http_timeout"
    except ssl.SSLError:
        return False, None, None, "tls_error"
    except (ConnectionError, OSError):
        return False, None, None, "network_error"
    except Exception as exc:  # defensive: a probe never raises outward
        return False, None, None, f"internal_error:{type(exc).__name__}"
    finally:
        if tunnel is not None:
            try:
                tunnel.close()
            except OSError:
                pass


def _read_head(sock: socket.socket) -> str:
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > _HEADER_BUF_LIMIT:
            raise ConnectionError("HTTP header block too large")
    return buffer.decode("latin1", errors="replace")


@dataclass
class CoreTester:
    """Runtime-test one node/core pair using the shared core lifecycle.

    Compatibility keeps its richer per-destination diagnostics, while process
    creation, secure config files, readiness waiting and cleanup are delegated
    to :class:`CoreRuntimeManager` so there is only one lifecycle
    implementation in the source tree.
    """

    core: str
    binary_path: Path
    config_builder: object
    config_writer: object
    argv_builder: object
    port_getter: object
    test_urls: Sequence[CompatTestUrl]
    startup_timeout: float = 8.0
    http_timeout: float = 8.0
    core_version: str | None = None
    process_timeout: float = 60.0

    def __post_init__(self) -> None:
        self._manager = CoreRuntimeManager(
            {self.core: Path(self.binary_path)},
            startup_timeout=self.startup_timeout,
        )

    @property
    def _processes(self) -> set:
        """Test/debug view of live processes; lifecycle ownership stays central."""
        return {session.process for session in self._manager._sessions}

    def test_node(
        self, config: ParsedConfig, resolved_ip: str | None = None
    ) -> CoreTestResult:
        result = CoreTestResult(core=self.core, core_version=self.core_version)
        session = None
        try:
            session = self._manager.open_with_adapter(
                self.core,
                Path(self.binary_path),
                config,
                builder=self.config_builder,
                writer=self.config_writer,
                argv_builder=self.argv_builder,
                port_getter=self.port_getter,
                server_override=resolved_ip,
            )
        except RuntimeCoreError as exc:
            result.status = "unsupported" if exc.category.startswith("config_unsupported:") else "fail"
            if exc.category.startswith("config_unsupported:"):
                result.failure_category = exc.category.split("config_unsupported:", 1)[1]
            elif exc.category == "core_startup_failed":
                result.failure_category = self._classify_startup_failure(exc.detail)
                result.detail = (exc.detail or "")[:200]
            else:
                result.failure_category = exc.category
            return result
        except Exception as exc:  # defensive: one node never kills the stage
            result.status = "fail"
            result.failure_category = f"internal_error:{type(exc).__name__}"
            return result

        try:
            result.status = "fail"
            result.failure_category = "all_http_failed"
            passed = 0
            latencies: list[float] = []
            reasons: set[str] = set()
            for test_url in self.test_urls:
                ok, status, latency, reason = fetch_via_local_proxy(
                    "127.0.0.1",
                    session.port,
                    test_url.url,
                    timeout=self.http_timeout,
                    expect_statuses=test_url.expect_statuses,
                    expect_substring=test_url.expect_substring,
                )
                result.probes.append({
                    "url_host": (test_url.url.split("/", 3)[2] if "://" in test_url.url else test_url.url),
                    "ok": ok,
                    "status": status,
                    "latency_ms": round(latency, 1) if latency is not None else None,
                    "failure_reason": reason,
                })
                if ok:
                    passed += 1
                    if latency is not None:
                        latencies.append(latency)
                elif reason:
                    reasons.add(reason)

            if passed > 0:
                result.status = "pass"
                result.failure_category = None
                result.latency_ms = sorted(latencies)[len(latencies) // 2] if latencies else None
            else:
                result.failure_category = self._classify_probe_failure(reasons, config=config)
            return result
        except Exception as exc:  # defensive: one node never kills the stage
            result.status = "fail"
            result.failure_category = f"internal_error:{type(exc).__name__}"
            return result
        finally:
            if session is not None:
                session.close()

    def cleanup(self) -> None:
        self._manager.cleanup()

    def _classify_startup_failure(self, stderr_tail: str) -> str:
        lowered = (stderr_tail or "").lower()
        for marker in _CONFIG_REJECTED_MARKERS:
            if marker in lowered:
                return "core_config_rejected"
        return "core_startup_failed"

    def _classify_probe_failure(self, reasons: set[str], *, config: ParsedConfig) -> str:
        if not reasons:
            return "HTTP_failure"
        priority = (
            "content_integrity_failure",
            "tls_error",
            "proxy_connect_failed",
            "http_timeout",
            "network_error",
        )
        for category in priority:
            if category in reasons:
                return self._final_category(category, config)
        first = sorted(reasons)[0]
        return self._final_category(first, config)

    def _final_category(self, raw: str, config: ParsedConfig) -> str:
        if raw == "tls_error":
            return "TLS_failure"
        if raw == "http_timeout":
            if config.protocol in ("hysteria2", "tuic"):
                return "UDP_unreachable"
            return "timeout"
        if raw == "proxy_connect_failed":
            host = config.host or ""
            if any(not ch.isdigit() and ch != "." for ch in host) and ":" not in host:
                return "DNS_failure"
            return "proxy_handshake_failed"
        if raw == "network_error":
            return "proxy_handshake_failed"
        if raw == "unexpected_status":
            return "HTTP_failure"
        return raw
