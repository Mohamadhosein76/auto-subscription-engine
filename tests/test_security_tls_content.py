"""Task 4 tests: TLS classification, HTTPS content integrity, no-bypass contract.

All offline; TLS errors are synthesized, content verdicts are evaluated
on fabricated probe objects. A localhost-only connection test covers the
inconclusive path (no external traffic).
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from pathlib import Path

import auto_subscription_engine.core.security.tlsprobe as tlsprobe
from auto_subscription_engine.core.security.tlsprobe import (
    CertSummary,
    EndpointProbe,
    NodeProbeResult,
    apply_content_expectations,
    classify_tls_error,
    probe_endpoint,
)

# ---------------------------------------------------------------------------
# TLS error classification
# ---------------------------------------------------------------------------


def _cert_error(message: str) -> ssl.SSLCertVerificationError:
    exc = ssl.SSLCertVerificationError(1, message)
    exc.verify_message = message
    return exc


def test_classify_hostname_mismatch():
    exc = _cert_error("certificate verify failed: Hostname mismatch")
    assert classify_tls_error(exc, "example.com") == "hostname_mismatch"


def test_classify_expired_certificate():
    exc = _cert_error("certificate verify failed: certificate has expired")
    assert classify_tls_error(exc, "example.com") == "certificate_expired_or_not_yet_valid"


def test_classify_not_yet_valid_certificate():
    exc = _cert_error("certificate verify failed: certificate is not yet valid")
    assert classify_tls_error(exc, "example.com") == "certificate_expired_or_not_yet_valid"


def test_classify_untrusted_issuer():
    exc = _cert_error("certificate verify failed: self signed certificate in certificate chain")
    assert classify_tls_error(exc, "example.com") == "untrusted_issuer"
    exc2 = _cert_error("certificate verify failed: unable to get local issuer certificate")
    assert classify_tls_error(exc2, "example.com") == "untrusted_issuer"


def test_classify_generic_verify_failure():
    exc = _cert_error("certificate verify failed: something unusual")
    assert classify_tls_error(exc, "example.com") == "certificate_verify_failed"


def test_classify_protocol_and_transport_errors():
    assert classify_tls_error(ssl.SSLError("wrong version")) == "tls_protocol_error"
    assert classify_tls_error(socket.timeout("timed out")) == "probe_timeout"
    assert classify_tls_error(ConnectionError("reset")) == "transport_error"


# ---------------------------------------------------------------------------
# Certificate metadata summary
# ---------------------------------------------------------------------------


def test_cert_summary_extraction():
    cert = {
        "issuer": ((("organizationName", "Example CA"),),),
        "subject": ((("commonName", "example.com"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Jan  1 00:00:00 2027 GMT",
    }
    der = b"\x30\x03\x02\x01\x00"
    summary = tlsprobe._summary_from_cert(cert, der)
    assert "Example CA" in (summary.issuer or "")
    assert "example.com" in (summary.subject or "")
    assert summary.san_domains == ["example.com", "www.example.com"]
    assert summary.fingerprint_sha256 == hashlib.sha256(der).hexdigest()


def test_fingerprint_change_is_not_an_attack_by_design():
    """Two different fingerprints are just metadata - no 'attacker' verdict."""
    a = tlsprobe._summary_from_cert({}, b"a" * 8)
    b = tlsprobe._summary_from_cert({}, b"b" * 8)
    assert a.fingerprint_sha256 != b.fingerprint_sha256
    assert a.fingerprint_sha256 and b.fingerprint_sha256


# ---------------------------------------------------------------------------
# Content expectations
# ---------------------------------------------------------------------------


def _ok_probe(url: str, body: bytes, status: int = 200) -> EndpointProbe:
    return EndpointProbe(
        endpoint=url,
        tls_ok=True,
        status=status,
        body_size=len(body),
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_text=body.decode("utf-8", errors="replace"),
        content_ok=True,
    )


def test_content_expectations_pass():
    probe = _ok_probe("https://x.example/robots.txt", b"User-agent: *\nDisallow:")
    apply_content_expectations(
        probe, {"url": "https://x.example/robots.txt", "expect_status": 200,
                "expect_substring": "User-agent"}
    )
    assert probe.content_ok and probe.content_failures == []


def test_content_bad_body_substring_missing():
    probe = _ok_probe("https://x.example/", b"totally unexpected body")
    apply_content_expectations(
        probe, {"url": "https://x.example/", "expect_status": 200,
                "expect_substring": "Example Domain"}
    )
    assert not probe.content_ok
    assert "substring_missing" in probe.content_failures


def test_content_wrong_status():
    probe = _ok_probe("https://x.example/", b"data", status=403)
    apply_content_expectations(probe, {"url": "https://x.example/", "expect_status": 200})
    assert not probe.content_ok
    assert any(f.startswith("status:") for f in probe.content_failures)


def test_content_exact_body_and_hash():
    probe = _ok_probe("https://x.example/", b"Example Domain")
    apply_content_expectations(
        probe, {"url": "https://x.example/", "expect_exact_body": "Example Domain"}
    )
    assert probe.content_ok
    apply_content_expectations(
        probe, {"url": "https://x.example/",
                "expect_body_hash": hashlib.sha256(b"other").hexdigest()}
    )
    assert "body_hash_mismatch" in probe.content_failures


def test_content_expect_empty():
    probe = _ok_probe("https://x.example/empty", b"")
    apply_content_expectations(probe, {"url": "https://x.example/empty", "expect_empty": True})
    assert probe.content_ok
    probe2 = _ok_probe("https://x.example/empty", b"something")
    apply_content_expectations(probe2, {"url": "https://x.example/empty", "expect_empty": True})
    assert "body_not_empty" in probe2.content_failures


def test_content_verdict_skipped_without_tls():
    probe = EndpointProbe(endpoint="https://x.example/", tls_ok=False, tls_error="hostname_mismatch")
    apply_content_expectations(probe, {"url": "https://x.example/", "expect_substring": "x"})
    assert probe.content_failures == []  # not judged: TLS never verified


# ---------------------------------------------------------------------------
# NodeProbeResult aggregation
# ---------------------------------------------------------------------------


def test_node_probe_result_counts():
    good = EndpointProbe(endpoint="a", tls_ok=True, status=200, content_ok=True)
    bad_content = EndpointProbe(endpoint="b", tls_ok=True, status=200,
                                content_failures=["substring_missing"], content_ok=False)
    bad_tls = EndpointProbe(endpoint="c", tls_ok=False,
                            tls_error="untrusted_issuer")
    inconclusive = EndpointProbe(endpoint="d", tls_ok=False, inconclusive=True,
                                 tls_error="probe_timeout")
    result = NodeProbeResult(endpoints=[good, bad_content, bad_tls, inconclusive])
    assert result.tls_ok_count == 2  # good + bad_content had valid TLS
    assert result.tls_cert_failures == 1  # inconclusive never counts as evidence
    assert result.tls_inconclusive == 1
    assert result.content_failures == 1
    assert result.cert_error_categories() == ["untrusted_issuer"]


def test_all_endpoints_failed_tls_is_mitm_evidence():
    probes = NodeProbeResult(endpoints=[
        EndpointProbe(endpoint="a", tls_ok=False, tls_error="untrusted_issuer"),
        EndpointProbe(endpoint="b", tls_ok=False, tls_error="hostname_mismatch"),
    ])
    assert probes.tls_cert_failures == 2
    assert probes.tls_ok_count == 0


# ---------------------------------------------------------------------------
# Real socket path (localhost only - no external traffic)
# ---------------------------------------------------------------------------


def test_probe_endpoint_inconclusive_on_dead_local_port():
    """A refused connection on 127.0.0.1 is inconclusive, never an anomaly."""
    # grab a free port, then release it
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    probe = probe_endpoint(
        "127.0.0.1", port, url="https://example.com/", timeout=0.5, max_body_bytes=1024
    )
    assert not probe.tls_ok
    assert probe.inconclusive
    assert probe.tls_error in ("transport_error", "proxy_connect_failed")


# ---------------------------------------------------------------------------
# Security contract: verification bypasses are forbidden in source
# ---------------------------------------------------------------------------


def test_no_tls_bypass_in_security_source():
    """Contract: no bypass patterns in *code* (docstrings/comments excluded)."""
    import io
    import tokenize

    source = Path(tlsprobe.__file__).read_text(encoding="utf-8")
    code_only = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type in (tokenize.STRING, tokenize.COMMENT):
            continue
        code_only.append(token.string)
    code = "\n".join(code_only).lower()
    assert "cert_none" not in code
    assert "check_hostname" not in code  # never touched -> default (True) stays
    assert "verify=false" not in code
    # the real code path always uses full verification
    assert "create_default_context" in code
