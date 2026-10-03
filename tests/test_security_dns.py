"""Task 4 tests: DNS security checks (system vs independent DoH).

Fully offline: both resolvers are injected; no network traffic happens.
"""

from __future__ import annotations

from auto_subscription_engine.core.security.dnscheck import (
    DnsEvidence,
    classify_ip,
    evaluate_host,
    evaluate_hosts,
    is_bogon,
    is_ip_literal,
)

DNS_CFG = {"doh_url": "https://dns.google/resolve", "timeout_seconds": 1, "concurrency": 4}


# ---------------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------------


def test_classify_ip_labels():
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("10.1.2.3") == "private"
    assert classify_ip("192.168.1.1") == "private"
    assert classify_ip("169.254.1.1") == "link_local"
    assert classify_ip("224.0.0.5") == "multicast"
    assert classify_ip("240.0.0.1") == "reserved"
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("not-an-ip") == "invalid"

def test_is_bogon_and_ip_literal():
    assert is_bogon("127.0.0.1")
    assert is_bogon("10.9.9.9")
    assert not is_bogon("93.184.216.34")
    assert is_ip_literal("8.8.8.8")
    assert not is_ip_literal("example.com")


# ---------------------------------------------------------------------------
# evaluate_host policy matrix
# ---------------------------------------------------------------------------


def test_ip_literal_needs_no_dns():
    evidence = evaluate_host("8.8.8.8", dns_cfg=DNS_CFG)
    assert evidence.host_kind == "ip_literal"
    assert evidence.status == "ip_literal"
    assert evidence.doh_available  # nothing external required
    assert evidence.anomaly is None


def test_both_resolvers_agree_public_is_clean():
    evidence = evaluate_host(
        "node.example", dns_cfg=DNS_CFG,
        system_resolver=lambda h: ["93.184.216.34"],
        doh_resolver=lambda h: ["93.184.216.34"],
    )
    assert evidence.status == "resolved"
    assert evidence.anomaly is None
    assert not evidence.benign_mismatch
    assert evidence.doh_available


def test_public_mismatch_is_warning_only_not_block():
    """CDN/GeoDNS legitimately differ - this must NOT be hard evidence."""
    evidence = evaluate_host(
        "cdn.example", dns_cfg=DNS_CFG,
        system_resolver=lambda h: ["8.8.8.8"],
        doh_resolver=lambda h: ["8.8.4.4"],
    )
    assert evidence.status == "resolved"
    assert evidence.anomaly is None
    assert evidence.benign_mismatch


def test_system_private_with_public_doh_is_rebinding_signature():
    """Mixed answers (one private, one public) = rebinding-class evidence."""
    evidence = evaluate_host(
        "mixed.example", dns_cfg=DNS_CFG,
        system_resolver=lambda h: ["10.0.0.5"],
        doh_resolver=lambda h: ["93.184.216.34"],
    )
    assert evidence.anomaly == "rebinding"


def test_all_private_answers_are_bogon_evidence():
    evidence = evaluate_host(
        "bogon.example", dns_cfg=DNS_CFG,
        system_resolver=lambda h: ["10.0.0.5"],
        doh_resolver=lambda h: [],
    )
    assert evidence.anomaly == "bogon_answer"
    assert evidence.system_bogons == ["10.0.0.5"]


def test_rebinding_signature_public_to_private():
    evidence = evaluate_host(
        "rebind.example", dns_cfg=DNS_CFG,
        system_resolver=lambda h: ["93.184.216.34"],
        doh_resolver=lambda h: ["192.168.0.1"],
    )
    assert evidence.anomaly == "rebinding"
    assert evidence.doh_bogons == ["192.168.0.1"]


def test_unresolved_from_all_resolvers():
    evidence = evaluate_host(
        "dead.example", dns_cfg=DNS_CFG,
        system_resolver=lambda h: [],
        doh_resolver=lambda h: [],
    )
    assert evidence.status == "unresolved"
    assert evidence.doh_available


def test_doh_unavailable_with_public_system_answer():
    """DoH outage is not the host's fault: record as incomplete, no anomaly."""
    evidence = evaluate_host(
        "ok.example", dns_cfg=DNS_CFG,
        system_resolver=lambda h: ["93.184.216.34"],
        doh_resolver=lambda h: None,
    )
    assert evidence.status == "system_only"
    assert not evidence.doh_available
    assert evidence.anomaly is None

def test_system_only_public_answer_no_anomaly():
    evidence = evaluate_host(
        "ok2.example", dns_cfg=DNS_CFG,
        system_resolver=lambda h: ["93.184.216.34"],
        doh_resolver=lambda h: [],
    )
    assert evidence.status == "system_only"
    assert evidence.anomaly is None


def test_malformed_doh_answer_data_ignored():
    """The real DoH parser skips non-IP answer data (A/AAAA only)."""
    class _FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "Answer": [
                    {"name": "weird.example", "type": 1, "data": "!!!"},
                    {"name": "weird.example", "type": 1, "data": "93.184.216.34"},
                    {"name": "weird.example", "type": 5, "data": "cname.example"},
                ]
            }

    class _FakeSession:
        def get(self, url, params=None, timeout=None):
            return _FakeResponse()

    from auto_subscription_engine.core.security.dnscheck import doh_resolve

    ips = doh_resolve(
        "weird.example", doh_url="https://dns.google/resolve",
        timeout=1, session=_FakeSession(),
    )
    assert ips == ["93.184.216.34"]


def test_evaluate_hosts_is_bounded_and_complete():
    hosts = [f"h{i}.example" for i in range(10)]
    results = evaluate_hosts(
        hosts,
        dns_cfg=DNS_CFG,
        system_resolver=lambda h: ["8.8.8.8"],
        doh_resolver=lambda h: ["8.8.8.8"],
    )
    assert set(results) == set(hosts)
    assert all(r.status == "resolved" for r in results.values())


def test_evaluate_hosts_resolver_crash_is_contained():
    def _boom(host):
        raise RuntimeError("resolver exploded")

    results = evaluate_hosts(
        ["a.example"], dns_cfg=DNS_CFG,
        system_resolver=_boom, doh_resolver=lambda h: ["8.8.8.8"],
    )
    assert "a.example" in results  # contained, never raised


def test_dns_evidence_to_dict_is_safe():
    evidence = DnsEvidence(
        host_kind="hostname", system_ips=["8.8.8.8"], doh_ips=["8.8.8.8"],
        status="resolved",
    )
    payload = evidence.to_dict()
    assert payload["status"] == "resolved"
    # no credential-shaped fields ever
    assert not any(k in payload for k in ("uri", "password", "uuid", "identity"))
