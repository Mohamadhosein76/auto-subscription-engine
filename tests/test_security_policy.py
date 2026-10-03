"""Task 4 tests: the security decision model and deterministic risk score."""

from __future__ import annotations

from auto_subscription_engine.core.security.asnmap import AsnInfo
from auto_subscription_engine.core.security.dnscheck import DnsEvidence
from auto_subscription_engine.core.security.policy import (
    STATUS_ALLOW,
    STATUS_ALLOW_WITH_WARNINGS,
    STATUS_BLOCK,
    STATUS_QUARANTINE,
    NodeSecurityEvidence,
    evaluate_node,
    risk_score,
    summarize_decisions,
)
from auto_subscription_engine.core.security.tlsprobe import (
    EndpointProbe,
    NodeProbeResult,
)

RISK_WEIGHTS = {
    "spamhaus_drop": 100,
    "asndrop": 100,
    "feodo": 100,
    "bogon": 100,
    "rebinding": 100,
    "tls_all_failed": 90,
    "content_multi": 80,
    "unresolved": 40,
    "content_single": 20,
    "mismatch": 10,
    "incomplete_probes": 5,
}


def _good_probes() -> NodeProbeResult:
    return NodeProbeResult(endpoints=[
        EndpointProbe(endpoint="a", tls_ok=True, status=200, content_ok=True),
        EndpointProbe(endpoint="b", tls_ok=True, status=200, content_ok=True),
    ])


def _clean_evidence(**overrides) -> NodeSecurityEvidence:
    fields = dict(
        resolved_ip="93.184.216.34",
        spamhaus_drop_hit=False,
        asndrop_hit=False,
        feodo_hit=False,
        dns=DnsEvidence(host_kind="ip_literal", status="ip_literal", doh_available=True),
        probes=_good_probes(),
        asn=AsnInfo(asn=64512, as_name="EXAMPLE-HOSTING", source="cymru_whois"),
        content_failure_threshold=2,
        quarantine_on_incomplete=False,
    )
    fields.update(overrides)
    return NodeSecurityEvidence(**fields)


def _all_tls_failed_probes() -> NodeProbeResult:
    return NodeProbeResult(endpoints=[
        EndpointProbe(endpoint="a", tls_ok=False, tls_error="untrusted_issuer"),
        EndpointProbe(endpoint="b", tls_ok=False, tls_error="hostname_mismatch"),
    ])


def _multi_content_failure_probes() -> NodeProbeResult:
    return NodeProbeResult(endpoints=[
        EndpointProbe(endpoint="a", tls_ok=True, status=200,
                      content_ok=False, content_failures=["substring_missing"]),
        EndpointProbe(endpoint="b", tls_ok=True, status=200,
                      content_ok=False, content_failures=["status:403!=200"]),
    ])


# ---------------------------------------------------------------------------
# ALLOW
# ---------------------------------------------------------------------------


def test_clean_node_is_allowed():
    decision = evaluate_node(_clean_evidence())
    assert decision.status == STATUS_ALLOW
    assert decision.risk_score == 0
    assert decision.checks_complete


# ---------------------------------------------------------------------------
# BLOCK (high-confidence evidence)
# ---------------------------------------------------------------------------


def test_spamhaus_drop_blocks():
    decision = evaluate_node(_clean_evidence(spamhaus_drop_hit=True))
    assert decision.status == STATUS_BLOCK
    assert "spamhaus_drop_endpoint_hit" in decision.reasons
    assert decision.risk_score == RISK_WEIGHTS["spamhaus_drop"]


def test_asndrop_blocks():
    decision = evaluate_node(_clean_evidence(asndrop_hit=True))
    assert decision.status == STATUS_BLOCK
    assert decision.risk_score == RISK_WEIGHTS["asndrop"]


def test_feodo_c2_blocks():
    decision = evaluate_node(_clean_evidence(feodo_hit=True))
    assert decision.status == STATUS_BLOCK
    assert decision.risk_score == RISK_WEIGHTS["feodo"]


def test_dns_private_answer_blocks():
    dns = DnsEvidence(host_kind="hostname", system_ips=["10.0.0.5"],
                      system_bogons=["10.0.0.5"], anomaly="bogon_answer",
                      status="resolved", doh_available=True)
    decision = evaluate_node(_clean_evidence(dns=dns))
    assert decision.status == STATUS_BLOCK
    assert decision.risk_score == RISK_WEIGHTS["bogon"]


def test_dns_rebinding_blocks():
    dns = DnsEvidence(
        host_kind="hostname", system_ips=["93.184.216.34"], doh_ips=["192.168.0.1"],
        doh_bogons=["192.168.0.1"], anomaly="rebinding", status="resolved",
        doh_available=True,
    )
    decision = evaluate_node(_clean_evidence(dns=dns))
    assert decision.status == STATUS_BLOCK
    assert "dns_rebinding_signature" in decision.reasons


def test_block_precedence_over_quarantine():
    """Reputation evidence wins even when TLS also failed."""
    decision = evaluate_node(_clean_evidence(
        spamhaus_drop_hit=True, probes=_all_tls_failed_probes(),
    ))
    assert decision.status == STATUS_BLOCK
    assert decision.risk_score == 100


# ---------------------------------------------------------------------------
# QUARANTINE
# ---------------------------------------------------------------------------


def test_all_tls_failures_quarantine():
    decision = evaluate_node(_clean_evidence(probes=_all_tls_failed_probes()))
    assert decision.status == STATUS_QUARANTINE
    assert decision.reasons[0].startswith("tls_validation_failed_all_endpoints")
    assert decision.risk_score == RISK_WEIGHTS["tls_all_failed"]


def test_multiple_content_integrity_failures_quarantine():
    decision = evaluate_node(_clean_evidence(probes=_multi_content_failure_probes()))
    assert decision.status == STATUS_QUARANTINE
    assert "https_content_integrity_failures" in decision.reasons
    assert decision.risk_score == RISK_WEIGHTS["content_multi"]


def test_unresolved_dns_quarantines():
    dns = DnsEvidence(host_kind="hostname", status="unresolved", doh_available=True)
    decision = evaluate_node(_clean_evidence(dns=dns))
    assert decision.status == STATUS_QUARANTINE
    assert decision.risk_score == RISK_WEIGHTS["unresolved"]


def test_partial_tls_failure_is_warning_not_quarantine():
    """One bad endpoint must not remove a node (flaky site ≠ MITM)."""
    probes = NodeProbeResult(endpoints=[
        EndpointProbe(endpoint="a", tls_ok=True, status=200, content_ok=True),
        EndpointProbe(endpoint="b", tls_ok=False, tls_error="untrusted_issuer"),
    ])
    decision = evaluate_node(_clean_evidence(probes=probes))
    assert decision.status in (STATUS_ALLOW, STATUS_ALLOW_WITH_WARNINGS)
    assert "https_content_single_endpoint_failure" not in decision.reasons


# ---------------------------------------------------------------------------
# ALLOW_WITH_WARNINGS (soft signals only)
# ---------------------------------------------------------------------------


def test_public_dns_mismatch_is_warning_only():
    dns = DnsEvidence(
        host_kind="hostname", system_ips=["8.8.8.8"], doh_ips=["8.8.4.4"],
        status="resolved", benign_mismatch=True, doh_available=True,
    )
    decision = evaluate_node(_clean_evidence(dns=dns))
    assert decision.status == STATUS_ALLOW_WITH_WARNINGS
    assert "dns_public_mismatch" in decision.warnings
    assert decision.risk_score == RISK_WEIGHTS["mismatch"]


def test_inconclusive_probes_publish_with_warnings_and_incomplete_flag():
    probes = NodeProbeResult(endpoints=[
        EndpointProbe(endpoint="a", tls_ok=False, inconclusive=True, tls_error="probe_timeout"),
        EndpointProbe(endpoint="b", tls_ok=False, inconclusive=True, tls_error="transport_error"),
    ])
    decision = evaluate_node(_clean_evidence(probes=probes))
    assert decision.status == STATUS_ALLOW_WITH_WARNINGS
    assert not decision.checks_complete
    assert decision.risk_score == RISK_WEIGHTS["incomplete_probes"]


def test_missing_probe_evidence_marks_checks_incomplete():
    """Unknown != Safe: no probe evidence is visible incompleteness."""
    decision = evaluate_node(_clean_evidence(probes=None))
    assert not decision.checks_complete
    assert "tls_probes_not_run" in decision.warnings
    assert decision.status == STATUS_ALLOW_WITH_WARNINGS


def test_unknown_asn_marks_checks_incomplete():
    decision = evaluate_node(_clean_evidence(asn=AsnInfo()))
    assert not decision.checks_complete
    assert decision.status == STATUS_ALLOW_WITH_WARNINGS  # warning, not quarantine


def test_quarantine_on_incomplete_policy():
    decision = evaluate_node(
        _clean_evidence(asn=AsnInfo(), quarantine_on_incomplete=True)
    )
    assert decision.status == STATUS_QUARANTINE
    assert "security_checks_incomplete" in decision.reasons


# ---------------------------------------------------------------------------
# Determinism & aggregation
# ---------------------------------------------------------------------------


def test_decisions_are_deterministic():
    probes = _multi_content_failure_probes()
    dns = DnsEvidence(
        host_kind="hostname", system_ips=["8.8.8.8"], doh_ips=["8.8.4.4"],
        status="resolved", benign_mismatch=True, doh_available=True,
    )
    runs = [
        evaluate_node(_clean_evidence(dns=dns, probes=probes)).to_dict()
        for _ in range(5)
    ]
    assert all(run == runs[0] for run in runs)


def test_risk_score_never_leaves_unit_range():
    worst = evaluate_node(_clean_evidence(
        spamhaus_drop_hit=True, asndrop_hit=True, feodo_hit=True,
        probes=_all_tls_failed_probes(),
    ))
    assert 0 <= worst.risk_score <= 100
    assert worst.risk_score == 100


def test_country_has_no_security_influence():
    """The evidence model has no country field at all - by design."""
    assert not any("country" in f for f in NodeSecurityEvidence.__dataclass_fields__)


def test_summarize_decisions_counts():
    decisions = {
        "a": evaluate_node(_clean_evidence()),
        "b": evaluate_node(_clean_evidence(feodo_hit=True)),
        "c": evaluate_node(_clean_evidence(spamhaus_drop_hit=True)),
        "d": evaluate_node(_clean_evidence(probes=_all_tls_failed_probes())),
        "e": evaluate_node(_clean_evidence(
            dns=DnsEvidence(status="unresolved", host_kind="hostname", doh_available=True)
        )),
    }
    counts = summarize_decisions(decisions)
    assert counts == {
        "security_allowed": 1,
        "security_allowed_with_warnings": 0,
        "security_quarantined": 2,
        "security_blocked": 2,
    }
