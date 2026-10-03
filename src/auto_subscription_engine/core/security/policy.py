"""Security decision model and deterministic risk scoring (Task 4).

Every LIVE node ends up in exactly one of four states:

- ``ALLOW``                — no significant evidence found
- ``ALLOW_WITH_WARNINGS``  — only soft signals (benign DNS mismatch,
                             a single flaky content endpoint, ASN
                             concentration handled at selection time)
- ``QUARANTINE``           — a significant TLS/DNS/content anomaly;
                             never published, not proven malicious
- ``BLOCK``                — high-confidence malicious evidence or a
                             security-invariant violation; never published

Only ALLOW / ALLOW_WITH_WARNINGS may enter the public subscription.

The numeric ``security_risk_score`` (0..100) is derived from the same
evidence via a fixed, deterministic table — identical evidence always
produces identical decisions and scores. Country has *no* influence.
Generic hosting/datacenter ASNs contribute zero: an ASN only matters
when the official Spamhaus ASN-DROP feed lists it, or when it belongs
to a Cloudflare network (project-wide Cloudflare-zero invariant).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .asnmap import AsnInfo
from .dnscheck import DnsEvidence
from .tlsprobe import NodeProbeResult

STATUS_ALLOW = "allow"
STATUS_ALLOW_WITH_WARNINGS = "allow_with_warnings"
STATUS_QUARANTINE = "quarantine"
STATUS_BLOCK = "block"

#: Statuses that may appear in the public subscription.
PUBLISHABLE_STATUSES = frozenset({STATUS_ALLOW, STATUS_ALLOW_WITH_WARNINGS})

# -- deterministic risk weights -------------------------------------------------

RISK_SPAMHAUS_DROP = 100
RISK_SPAMHAUS_ASNDROP = 100
RISK_FEODO_C2 = 100
RISK_CLOUDFLARE_NETWORK = 100
RISK_DNS_BOGON = 100
RISK_DNS_REBINDING = 100
RISK_TLS_ALL_CERT_FAILED = 90
RISK_CONTENT_MULTI_FAILURE = 80
RISK_DNS_UNRESOLVED = 40
RISK_CONTENT_SINGLE_FAILURE = 20
RISK_DNS_PUBLIC_MISMATCH = 10
RISK_PROBES_INCOMPLETE = 5
RISK_ASN_UNKNOWN = 0          # unknown ASN: metadata gap, not malice
                              # (but publish requires a known ASN - see
                              # require_asn / asn_unknown quarantine)
RISK_GENERIC_HOSTING = 0      # hosting alone is never a signal

#: Project invariant: Cloudflare must be completely zero - not only as a
#: dependency/service, but also as the final endpoint network. Endpoints
#: announced by these Cloudflare-owned ASNs are hard-blocked with the
#: maximum risk score. Extendable via ``security.policy.forbidden_asns``.
DEFAULT_FORBIDDEN_ASNS = frozenset({13335, 209242})

#: Defense-in-depth identity matcher for Cloudflare organisations in AS
#: names. Deliberately NOT a raw substring test: only the standalone
#: tokens "CLOUDFLARE" / "CLOUDFLARENET" match (word boundaries), so a
#: name like "ACLOUDFLAREIMITATOR" or "CLOUDFLARELIKE-HOSTING" can never
#: produce a false positive.
_CLOUDFLARE_NAME_RE = re.compile(r"\bCLOUDFLARE(?:NET)?\b")


def is_cloudflare_org_name(as_name: str | None) -> bool:
    """True only for explicit Cloudflare organisation identities.

    Matching happens on a whitespace/punctuation-normalised, upper-cased
    copy of the AS name with word boundaries, so "Cloudflare, Inc.",
    "Cloudflare", "CLOUDFLARENET" and "CLOUDFLARESPECTRUM - Cloudflare
    London, LLC" all match, while any name that merely *contains* the
    letters (without the standalone word) does not.
    """
    if not as_name:
        return False
    normalized = " ".join(str(as_name).upper().split())
    return bool(_CLOUDFLARE_NAME_RE.search(normalized))

#: Generic datacenter/cloud ASN *names* (informational only, never a
#: block reason). Matching is a loose substring test on the AS name.
KNOWN_HOSTING_FRAGMENTS = (
    "amazon", "aws", "google", "microsoft", "azure", "ovh", "hetzner",
    "digitalocean", "linode", "akamai", "oracle", "alibaba", "choopa",
    "vultr", "contabo", "leaseweb",
)


@dataclass
class SecurityDecision:
    """Outcome of the policy evaluation for one node (credential-free)."""

    status: str = STATUS_ALLOW
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks_complete: bool = True

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "risk_score": self.risk_score,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "checks_complete": self.checks_complete,
        }


@dataclass
class NodeSecurityEvidence:
    """Everything the policy needs to judge one node."""

    resolved_ip: str | None = None
    spamhaus_drop_hit: bool = False
    asndrop_hit: bool = False
    feodo_hit: bool = False
    #: Endpoint ASN is on the forbidden-network list (Cloudflare).
    cloudflare_network_hit: bool = False
    #: AS organisation name explicitly identifies Cloudflare while the
    #: ASN itself is not on the forbidden list (defense-in-depth).
    cloudflare_org_hit: bool = False
    #: Publishing requires a determined ASN: an endpoint whose ASN cannot
    #: be established cannot be proven non-Cloudflare -> QUARANTINE.
    require_asn: bool = False
    dns: DnsEvidence | None = None
    probes: NodeProbeResult | None = None
    asn: AsnInfo | None = None
    content_failure_threshold: int = 2
    quarantine_on_incomplete: bool = False


def risk_score(evidence: NodeSecurityEvidence) -> int:
    """Deterministic 0..100 risk score for the given evidence."""
    score = 0
    if evidence.spamhaus_drop_hit:
        score = max(score, RISK_SPAMHAUS_DROP)
    if evidence.asndrop_hit:
        score = max(score, RISK_SPAMHAUS_ASNDROP)
    if evidence.feodo_hit:
        score = max(score, RISK_FEODO_C2)
    if evidence.cloudflare_network_hit or evidence.cloudflare_org_hit:
        score = max(score, RISK_CLOUDFLARE_NETWORK)

    dns = evidence.dns
    if dns is not None:
        if dns.anomaly == "rebinding":
            score = max(score, RISK_DNS_REBINDING)
        elif dns.anomaly == "bogon_answer":
            score = max(score, RISK_DNS_BOGON)
        elif dns.status == "unresolved":
            score = max(score, RISK_DNS_UNRESOLVED)
        elif dns.benign_mismatch:
            score = max(score, RISK_DNS_PUBLIC_MISMATCH)

    probes = evidence.probes
    if probes is not None and probes.endpoints:
        if probes.tls_cert_failures > 0 and probes.tls_ok_count == 0:
            score = max(score, RISK_TLS_ALL_CERT_FAILED)
        if probes.content_failures >= max(2, int(evidence.content_failure_threshold)):
            score = max(score, RISK_CONTENT_MULTI_FAILURE)
        elif probes.content_failures == 1:
            score = max(score, RISK_CONTENT_SINGLE_FAILURE)
        if probes.tls_inconclusive == len(probes.endpoints):
            score = max(score, RISK_PROBES_INCOMPLETE)
    return min(100, score)


def evaluate_node(evidence: NodeSecurityEvidence) -> SecurityDecision:
    """Deterministic security verdict for one LIVE node."""
    decision = SecurityDecision()
    decision.risk_score = risk_score(evidence)

    # -- hard evidence first (BLOCK) --------------------------------------
    if evidence.spamhaus_drop_hit:
        decision.status = STATUS_BLOCK
        decision.reasons.append("spamhaus_drop_endpoint_hit")
    if evidence.asndrop_hit:
        decision.status = STATUS_BLOCK
        decision.reasons.append("spamhaus_asndrop_hit")
    if evidence.feodo_hit:
        decision.status = STATUS_BLOCK
        decision.reasons.append("feodo_active_c2_hit")
    if evidence.cloudflare_network_hit:
        decision.status = STATUS_BLOCK
        decision.reasons.append("cloudflare_network_forbidden")
    elif evidence.cloudflare_org_hit:
        decision.status = STATUS_BLOCK
        decision.reasons.append("cloudflare_org_identity")

    dns = evidence.dns
    if dns is not None:
        if dns.anomaly == "rebinding":
            decision.status = STATUS_BLOCK
            decision.reasons.append("dns_rebinding_signature")
        elif dns.anomaly == "bogon_answer":
            decision.status = STATUS_BLOCK
            decision.reasons.append("dns_bogon_answer")
        elif dns.status == "unresolved":
            if decision.status == STATUS_ALLOW:
                decision.status = STATUS_QUARANTINE
                decision.reasons.append("dns_unresolved_all_resolvers")

    probes = evidence.probes
    if probes is not None and probes.endpoints:
        # All endpoints failing TLS validation = interception-class
        # anomaly (QUARANTINE; the evidence is strong but the node is
        # not proven malicious — an upstream could block test hosts).
        if probes.tls_cert_failures > 0 and probes.tls_ok_count == 0:
            if decision.status in (STATUS_ALLOW, STATUS_ALLOW_WITH_WARNINGS):
                decision.status = STATUS_QUARANTINE
                decision.reasons.append(
                    "tls_validation_failed_all_endpoints:"
                    + (",".join(probes.cert_error_categories()) or "unknown")
                )
        if probes.content_failures >= max(2, int(evidence.content_failure_threshold)):
            if decision.status in (STATUS_ALLOW, STATUS_ALLOW_WITH_WARNINGS):
                decision.status = STATUS_QUARANTINE
                decision.reasons.append("https_content_integrity_failures")
        elif probes.content_failures == 1:
            decision.warnings.append("https_content_single_endpoint_failure")

        if probes.tls_inconclusive == len(probes.endpoints) and not probes.tls_ok_count:
            decision.warnings.append("security_probes_inconclusive")

    # -- completeness -------------------------------------------------------
    complete = True
    if probes is None or not probes.endpoints:
        # No probe evidence at all (core missing, config unbuildable):
        # honest metadata - this node's checks are NOT complete.
        complete = False
        decision.warnings.append("tls_probes_not_run")
    if dns is not None and not dns.doh_available and dns.host_kind == "hostname":
        complete = False
        decision.warnings.append("doh_unavailable")
    if probes is not None and probes.endpoints and probes.tls_inconclusive == len(probes.endpoints):
        complete = False
    asn_unknown = evidence.asn is None or evidence.asn.asn is None
    if asn_unknown:
        complete = False
        decision.warnings.append("asn_lookup_unavailable")
    decision.checks_complete = complete

    if not complete:
        if evidence.quarantine_on_incomplete and decision.status in (
            STATUS_ALLOW,
            STATUS_ALLOW_WITH_WARNINGS,
        ):
            decision.status = STATUS_QUARANTINE
            decision.reasons.append("security_checks_incomplete")

    # Publish-side guarantee: without a determined ASN the engine cannot
    # prove the endpoint is not on a Cloudflare network, so the node is
    # quarantined (never ALLOW) until its ASN is known. A BLOCK verdict
    # from stronger evidence is never downgraded.
    if asn_unknown and evidence.require_asn and decision.status in (
        STATUS_ALLOW,
        STATUS_ALLOW_WITH_WARNINGS,
    ):
        decision.status = STATUS_QUARANTINE
        decision.reasons.append("asn_unknown")

    # -- warnings only (soft signals) ---------------------------------------
    if dns is not None and dns.benign_mismatch and decision.status == STATUS_ALLOW:
        decision.status = STATUS_ALLOW_WITH_WARNINGS
        decision.warnings.append("dns_public_mismatch")

    if decision.warnings and decision.status == STATUS_ALLOW:
        decision.status = STATUS_ALLOW_WITH_WARNINGS

    decision.warnings = sorted(dict.fromkeys(decision.warnings))
    decision.reasons = list(dict.fromkeys(decision.reasons))
    return decision


def summarize_decisions(decisions: dict[str, SecurityDecision]) -> dict[str, Any]:
    """Aggregate counters for live_stats.json (requirement 15)."""
    counts = {
        "security_allowed": 0,
        "security_allowed_with_warnings": 0,
        "security_quarantined": 0,
        "security_blocked": 0,
    }
    for decision in decisions.values():
        if decision.status == STATUS_ALLOW:
            counts["security_allowed"] += 1
        elif decision.status == STATUS_ALLOW_WITH_WARNINGS:
            counts["security_allowed_with_warnings"] += 1
        elif decision.status == STATUS_QUARANTINE:
            counts["security_quarantined"] += 1
        else:
            counts["security_blocked"] += 1
    return counts
