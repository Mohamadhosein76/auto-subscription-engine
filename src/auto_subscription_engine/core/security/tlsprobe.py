"""TLS deep check + HTTPS content integrity through the live proxy.

For every LIVE node the stage spawns the pinned sing-box core with that
node's config (same safe lifecycle as the connectivity stage), then —
through the *tunnel* — performs real HTTPS probes against a few tiny,
stable integrity endpoints operated by independent organizations
(deliberately none served by a Cloudflare edge).

TLS rules (no bypasses, ever):

- normal certificate verification AND hostname verification are always
  on (``ssl.create_default_context()``);
- ``CERT_NONE`` / ``check_hostname=False`` / ``verify=False`` are
  forbidden and never appear;
- verification failures are classified (hostname mismatch, expired,
  untrusted issuer, verify-failed) and become QUARANTINE evidence when
  *every* configured endpoint fails;
- inconclusive transport failures (timeouts, dead tunnel) are NOT
  anomalies by themselves — they only mark the node's checks incomplete.

Content rules:

- expected status / expected substring / expected exact body /
  expected body hash / expected empty body per endpoint;
- failures across >= ``failure_threshold`` independent endpoints =>
  content-integrity anomaly (impossible content after verified TLS is
  hard MITM evidence; policy maps it to QUARANTINE);
- a single failing endpoint is only a warning (one flaky site must not
  wrongly remove a node).

Certificate *metadata* (issuer, subject/SAN summary, validity window,
SHA-256 fingerprint) is kept for diagnostics. A changed fingerprint is
never treated as an attack by itself — CDNs rotate certificates.

All probe state is per-call (thread-safe under the bounded executor);
no body is retained beyond the bounded per-probe buffer.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import ssl
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from ..models import ParsedConfig
from ..utils.redaction import node_log
from ..clients.runtime import CoreRuntimeManager, RuntimeCoreError
from ..version import HTTP_USER_AGENT

logger = logging.getLogger(__name__)

_HEADER_BUF_LIMIT = 64 * 1024
_USER_AGENT = HTTP_USER_AGENT


# ---------------------------------------------------------------------------
# Evidence models (credential-free)
# ---------------------------------------------------------------------------


@dataclass
class CertSummary:
    """Safe certificate metadata for diagnostics (no secrets involved)."""

    issuer: str | None = None
    subject: str | None = None
    san_domains: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    fingerprint_sha256: str | None = None

    def to_dict(self) -> dict:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "san_domains": list(self.san_domains)[:8],
            "not_before": self.not_before,
            "not_after": self.not_after,
            "fingerprint_sha256": self.fingerprint_sha256,
        }


@dataclass
class EndpointProbe:
    """Result of one HTTPS probe through the tunnel."""

    endpoint: str
    tls_ok: bool = False
    tls_error: str | None = None
    inconclusive: bool = False
    status: int | None = None
    content_ok: bool = False
    content_failures: list[str] = field(default_factory=list)
    body_sha256: str | None = None
    body_size: int = 0
    #: Bounded body text (utf-8, replacement-decoded) for substring checks.
    body_text: str | None = None
    cert: CertSummary | None = None
    latency_ms: float | None = None

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "tls_ok": self.tls_ok,
            "tls_error": self.tls_error,
            "inconclusive": self.inconclusive,
            "status": self.status,
            "content_ok": self.content_ok,
            "content_failures": list(self.content_failures),
            "body_sha256": self.body_sha256,
            "body_size": self.body_size,
            "cert": self.cert.to_dict() if self.cert else None,
        }


@dataclass
class NodeProbeResult:
    """Aggregated TLS/content evidence for one node."""

    endpoints: list[EndpointProbe] = field(default_factory=list)
    core_started: bool = False
    runtime_core: str | None = None

    @property
    def tls_cert_failures(self) -> int:
        return sum(
            1 for e in self.endpoints
            if not e.tls_ok and not e.inconclusive and e.tls_error
        )

    @property
    def tls_inconclusive(self) -> int:
        return sum(1 for e in self.endpoints if e.inconclusive)

    @property
    def tls_ok_count(self) -> int:
        return sum(1 for e in self.endpoints if e.tls_ok)

    @property
    def content_failures(self) -> int:
        """Failed integrity checks on endpoints whose TLS was verified."""
        return sum(
            1 for e in self.endpoints
            if e.tls_ok and not e.content_ok and not e.inconclusive
        )

    @property
    def content_checked(self) -> int:
        return sum(1 for e in self.endpoints if e.tls_ok)

    def cert_error_categories(self) -> list[str]:
        return sorted(
            {e.tls_error for e in self.endpoints if e.tls_error and not e.inconclusive}
        )

    def certs(self) -> list[CertSummary]:
        return [e.cert for e in self.endpoints if e.cert is not None]

    def to_dict(self) -> dict:
        return {
            "core_started": self.core_started,
            "endpoints": [e.to_dict() for e in self.endpoints],
        }


# ---------------------------------------------------------------------------
# TLS failure classification
# ---------------------------------------------------------------------------


def classify_tls_error(exc: Exception, hostname: str | None = None) -> str:
    """Map an SSL error onto a stable, credential-free category."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        message = str(getattr(exc, "verify_message", "") or str(exc)).lower()
        if "hostname mismatch" in message or (
            hostname and "doesn't match" in message
        ):
            return "hostname_mismatch"
        if "expired" in message or "not yet valid" in message:
            return "certificate_expired_or_not_yet_valid"
        if (
            "unable to get local issuer" in message
            or "self signed" in message
            or "self-signed" in message
        ):
            return "untrusted_issuer"
        return "certificate_verify_failed"
    if isinstance(exc, ssl.SSLError):
        return "tls_protocol_error"
    if isinstance(exc, socket.timeout):
        return "probe_timeout"
    return "transport_error"


def _summary_from_cert(cert: dict, der: bytes | None) -> CertSummary:
    """Extract safe metadata from ``getpeercert()`` output."""
    issuer_parts = []
    for rdn in cert.get("issuer", ()) or ():
        for key, value in rdn:
            issuer_parts.append(f"{key}={value}")
    subject_parts = []
    for rdn in cert.get("subject", ()) or ():
        for key, value in rdn:
            subject_parts.append(f"{key}={value}")
    san = []
    for key, value in cert.get("subjectAltName", ()) or ():
        if key == "DNS" and isinstance(value, str):
            san.append(value)
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    fingerprint = hashlib.sha256(der).hexdigest() if der else None
    return CertSummary(
        issuer=", ".join(issuer_parts)[:200] or None,
        subject=", ".join(subject_parts)[:200] or None,
        san_domains=san,
        not_before=str(not_before) if not_before else None,
        not_after=str(not_after) if not_after else None,
        fingerprint_sha256=fingerprint,
    )


# ---------------------------------------------------------------------------
# Raw probe through the tunnel
# ---------------------------------------------------------------------------


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


def probe_endpoint(
    proxy_host: str,
    proxy_port: int,
    *,
    url: str,
    timeout: float,
    max_body_bytes: int,
) -> EndpointProbe:
    """One full HTTPS probe: CONNECT -> verified TLS -> GET -> bounded body.

    Never raises for endpoint-level problems; every outcome is recorded
    on the returned :class:`EndpointProbe`. The body is buffered up to
    ``max_body_bytes`` so substring/hash expectations can be evaluated.
    """
    parts = urlsplit(url)
    target_host = parts.hostname or ""
    target_port = parts.port or 443
    target_path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    probe = EndpointProbe(endpoint=url)
    started = time.perf_counter()

    tunnel: socket.socket | None = None
    try:
        tunnel = socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout)
        tunnel.settimeout(timeout)
        request = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n\r\n"
        )
        tunnel.sendall(request.encode("ascii"))
        head = _read_head(tunnel)
        status_line = head.split("\r\n", 1)[0]
        try:
            connect_status = int(status_line.split()[1])
        except (IndexError, ValueError):
            raise ConnectionError("malformed proxy CONNECT response")
        if not 200 <= connect_status < 300:
            probe.inconclusive = True
            probe.tls_error = "proxy_connect_failed"
            return probe

        # Full verification: CA chain + hostname. No bypass is possible
        # by construction (create_default_context sets both).
        context = ssl.create_default_context()
        tls = context.wrap_socket(tunnel, server_hostname=target_host)
        tunnel = tls
        probe.cert = _summary_from_cert(
            tls.getpeercert() or {},
            tls.getpeercert(binary_form=True),
        )
        probe.tls_ok = True

        get_request = (
            f"GET {target_path} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"User-Agent: {_USER_AGENT}\r\n"
            "Connection: close\r\n\r\n"
        )
        tunnel.sendall(get_request.encode("ascii"))
        response_head = _read_head(tunnel)
        status = int(response_head.split("\r\n", 1)[0].split()[1])
        probe.status = status
        body = b""
        while len(body) < int(max_body_bytes):
            chunk = tunnel.recv(16 * 1024)
            if not chunk:
                break
            body += chunk
        probe.body_size = len(body)
        probe.body_sha256 = hashlib.sha256(body).hexdigest()
        probe.body_text = body.decode("utf-8", errors="replace")
        probe.latency_ms = (time.perf_counter() - started) * 1000.0
        probe.content_ok = True  # verdict applied by apply_content_expectations
        return probe
    except ssl.SSLError as exc:
        category = classify_tls_error(exc, target_host)
        probe.tls_ok = False
        probe.tls_error = category
        probe.inconclusive = category in ("probe_timeout",)
        return probe
    except socket.timeout:
        probe.tls_ok = False
        probe.inconclusive = True
        probe.tls_error = "probe_timeout"
        return probe
    except (ConnectionError, OSError):
        probe.tls_ok = False
        probe.inconclusive = True
        probe.tls_error = "transport_error"
        return probe
    except Exception as exc:  # defensive: a probe must never raise outward
        probe.tls_ok = False
        probe.inconclusive = True
        probe.tls_error = f"internal_error:{type(exc).__name__}"
        node_log(
            logger,
            logging.DEBUG,
            ParsedConfig(protocol="security_probe", host=target_host, port=target_port),
            str(exc),
        )
        return probe
    finally:
        if tunnel is not None:
            try:
                tunnel.close()
            except OSError:
                pass


def apply_content_expectations(probe: EndpointProbe, endpoint_cfg: dict) -> EndpointProbe:
    """Evaluate the configured content expectations on a completed probe.

    Expectations (any combination): ``expect_status``, ``expect_empty``,
    ``expect_body_hash`` (sha256 hex of the first ``max_body_bytes``),
    ``expect_exact_body`` (utf-8), ``expect_substring``. Failures are
    listed on the probe; only TLS-verified probes are judged.
    """
    if not probe.tls_ok or probe.status is None:
        return probe
    failures: list[str] = []
    expect_status = endpoint_cfg.get("expect_status")
    if expect_status is not None and probe.status != int(expect_status):
        failures.append(f"status:{probe.status}!={expect_status}")
    if endpoint_cfg.get("expect_empty") and probe.body_size != 0:
        failures.append("body_not_empty")
    expected_hash = endpoint_cfg.get("expect_body_hash")
    if expected_hash and (probe.body_sha256 or "") != str(expected_hash).lower():
        failures.append("body_hash_mismatch")
    expected_exact = endpoint_cfg.get("expect_exact_body")
    if expected_exact is not None and probe.body_text is not None:
        if probe.body_text != str(expected_exact):
            failures.append("exact_body_mismatch")
    expected_substring = endpoint_cfg.get("expect_substring")
    if expected_substring is not None:
        if probe.body_text is None:
            failures.append("body_unavailable")
        elif str(expected_substring) not in probe.body_text:
            failures.append("substring_missing")
    probe.content_failures = failures
    probe.content_ok = not failures
    return probe


# ---------------------------------------------------------------------------
# Per-node runner (core lifecycle identical to the connectivity stage)
# ---------------------------------------------------------------------------


class SecurityProbeRunner:
    """Run security TLS/content probes through a compatible verified core."""

    def __init__(
        self,
        core_paths: dict[str, Path],
        *,
        endpoints: Sequence[dict],
        startup_timeout: float = 5.0,
        timeout: float = 8.0,
        max_body_bytes: int = 65536,
        workdir_root: Path | None = None,
    ) -> None:
        self.endpoints = [dict(e) for e in endpoints]
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes
        self.manager = CoreRuntimeManager(
            core_paths, startup_timeout=startup_timeout, workdir_root=workdir_root
        )

    def probe_node(
        self,
        config: ParsedConfig,
        resolved_ip: str | None = None,
        preferred_core: str | None = None,
    ) -> NodeProbeResult:
        """Run every integrity endpoint through one node; never raises."""
        outcome = NodeProbeResult()
        preferred = []
        if preferred_core:
            preferred.append(preferred_core)
        preferred.extend(
            core for core in CoreRuntimeManager.DEFAULT_ORDER if core not in preferred
        )
        cores = self.manager.candidate_cores(config, preferred=preferred)
        for core in cores:
            try:
                session = self.manager.open(core, config, server_override=resolved_ip)
            except RuntimeCoreError:
                continue
            try:
                outcome.core_started = True
                outcome.runtime_core = core
                for endpoint_cfg in self.endpoints:
                    probe = probe_endpoint(
                        "127.0.0.1",
                        session.port,
                        url=str(endpoint_cfg.get("url") or ""),
                        timeout=self.timeout,
                        max_body_bytes=self.max_body_bytes,
                    )
                    if probe.tls_ok:
                        apply_content_expectations(probe, endpoint_cfg)
                    outcome.endpoints.append(probe)
                return outcome
            except Exception:  # noqa: BLE001
                outcome = NodeProbeResult()
            finally:
                session.close()
        return outcome

    def cleanup(self) -> None:
        self.manager.cleanup()
