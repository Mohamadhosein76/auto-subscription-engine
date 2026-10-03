"""DNS security checks: system resolver vs independent DoH comparison.

For every hostname endpoint the stage compares:

- the **system DNS** answer (what the runner's resolver says), and
- an **independent public DoH** answer (Google Public DNS,
  ``dns.google`` — deliberately chosen because Cloudflare is banned
  project-wide and no API key is needed).

Policy (documented, deliberately conservative — CDN/GeoDNS make plain
mismatches *normal*):

- any answer containing loopback / private / link-local / multicast /
  reserved space  -> security invariant violation  -> BLOCK evidence
- public -> private flip between resolvers (rebinding signature) -> BLOCK
- both resolvers fail                      -> QUARANTINE (unresolvable)
- both answer, differing *public* sets     -> benign mismatch warning
- DoH unavailable while system is public   -> incomplete check (warning)

Evidence fields are credential-free: only IPs and classification labels.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests

from ..network import (
    classify_ip,
    doh_json_resolve,
    is_bogon,
    is_ip_literal,
    system_resolve,
)

logger = logging.getLogger(__name__)

_STATUS_IP_LITERAL = "ip_literal"
_STATUS_RESOLVED = "resolved"
_STATUS_SYSTEM_ONLY = "system_only"
_STATUS_UNRESOLVED = "unresolved"
_STATUS_DOH_ERROR = "doh_error"

doh_resolve = doh_json_resolve


@dataclass
class DnsEvidence:
    """Credential-free DNS evidence for one endpoint host."""

    host_kind: str = "hostname"  # or "ip_literal"
    system_ips: list[str] = field(default_factory=list)
    doh_ips: list[str] = field(default_factory=list)
    system_bogons: list[str] = field(default_factory=list)
    doh_bogons: list[str] = field(default_factory=list)
    status: str = _STATUS_UNRESOLVED
    anomaly: str | None = None  # "bogon_answer" | "rebinding" | None
    benign_mismatch: bool = False
    doh_available: bool = False

    @property
    def resolved_ips(self) -> list[str]:
        """System answer first (that is what the tunnel would use)."""
        return self.system_ips or self.doh_ips

    def to_dict(self) -> dict:
        return {
            "host_kind": self.host_kind,
            "status": self.status,
            "system_ips": list(self.system_ips),
            "doh_ips": list(self.doh_ips),
            "system_bogons": list(self.system_bogons),
            "doh_bogons": list(self.doh_bogons),
            "anomaly": self.anomaly,
            "benign_mismatch": self.benign_mismatch,
            "doh_available": self.doh_available,
        }


def evaluate_host(
    host: str,
    *,
    dns_cfg: dict,
    session: requests.Session | None = None,
    system_resolver=None,
    doh_resolver=None,
) -> DnsEvidence:
    """Full DNS security evaluation for one endpoint host."""
    evidence = DnsEvidence()
    if is_ip_literal(host):
        evidence.host_kind = "ip_literal"
        evidence.status = _STATUS_IP_LITERAL
        evidence.system_ips = [str(host).strip()]
        evidence.doh_available = True  # nothing external needed
        return evidence

    system = (
        system_resolver(host) if system_resolver
        else system_resolve(host)
    )
    doh = (
        doh_resolver(host) if doh_resolver
        else doh_resolve(
            host,
            doh_url=str(dns_cfg.get("doh_url", "https://dns.google/resolve")),
            timeout=float(dns_cfg.get("timeout_seconds", 5.0)),
            session=session,
        )
    )
    evidence.system_ips = list(system)
    evidence.system_bogons = [ip for ip in system if is_bogon(ip)]
    if doh is None:
        # Provider unavailable: never a host verdict by itself.
        evidence.doh_available = False
        if system:
            evidence.status = _STATUS_SYSTEM_ONLY
            if evidence.system_bogons:
                evidence.anomaly = "bogon_answer"
        else:
            evidence.status = _STATUS_UNRESOLVED
        return evidence

    evidence.doh_available = True
    evidence.doh_ips = list(doh)
    evidence.doh_bogons = [ip for ip in doh if is_bogon(ip)]

    if evidence.system_bogons or evidence.doh_bogons:
        evidence.status = _STATUS_RESOLVED
        system_public = [ip for ip in system if not is_bogon(ip)]
        doh_public = [ip for ip in doh if not is_bogon(ip)]
        mixed = (
            (evidence.system_bogons and doh_public)
            or (evidence.doh_bogons and system_public)
        )
        # Mixed public/private answers are the rebinding signature; an
        # all-bogon (or bogon-only) answer is a direct invariant violation.
        evidence.anomaly = "rebinding" if mixed else "bogon_answer"
        return evidence

    if not system and not doh:
        evidence.status = _STATUS_UNRESOLVED
        return evidence
    if not system and doh:
        # System failed but the independent DoH answer is public and
        # usable; record the resolver gap as an ordinary resolved case.
        evidence.status = _STATUS_RESOLVED
        evidence.benign_mismatch = False
        return evidence
    if system and not doh:
        evidence.status = _STATUS_SYSTEM_ONLY
        return evidence

    evidence.status = _STATUS_RESOLVED
    system_public = {ip for ip in system if not is_bogon(ip)}
    doh_public = {ip for ip in doh if not is_bogon(ip)}
    evidence.benign_mismatch = bool(system_public) and bool(doh_public) and (
        system_public != doh_public
    )
    return evidence


def evaluate_hosts(
    hosts: list[str],
    *,
    dns_cfg: dict,
    session: requests.Session | None = None,
    system_resolver=None,
    doh_resolver=None,
) -> dict[str, DnsEvidence]:
    """Evaluate many hosts with bounded concurrency (deterministic output)."""
    results: dict[str, DnsEvidence] = {}
    unique = list(dict.fromkeys(h for h in hosts if h))
    if not unique:
        return results
    concurrency = max(1, int(dns_cfg.get("concurrency", 8)))
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {
            pool.submit(
                evaluate_host,
                host,
                dns_cfg=dns_cfg,
                session=session,
                system_resolver=system_resolver,
                doh_resolver=doh_resolver,
            ): host
            for host in unique
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                results[host] = future.result()
            except Exception as exc:  # defensive: one bad host never kills the stage
                logger.debug("dns check failed for a host: %s", type(exc).__name__)
                results[host] = DnsEvidence(status=_STATUS_DOH_ERROR, doh_available=False)
    return results
