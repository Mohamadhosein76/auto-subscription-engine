"""Security Intelligence Layer (Task 4).

Pipeline position:

    ... -> Real Proxy Validation -> **Security Deep Check** -> Policy
          -> Ranking (ASN diversity) -> Guarded Publish

Modules:

- :mod:`.config`    — bounded, publishable defaults
- :mod:`.feedcache` — persistent, verified feed cache (data/security/)
- :mod:`.feeds`     — Spamhaus DROP/DROPv6/ASN-DROP + Feodo recommended
- :mod:`.asnmap`    — Team Cymru bulk + RIPEstat fallback, per-IP cache
- :mod:`.dnscheck`  — system vs independent DoH, bogon/rebinding checks
- :mod:`.tlsprobe`  — through-proxy TLS (full verification) + content
- :mod:`.policy`    — ALLOW / ALLOW_WITH_WARNINGS / QUARANTINE / BLOCK
- :mod:`.engine`    — stage orchestration + output rewriting
- :mod:`.verify`    — pre-publish security verification
"""

from .config import DEFAULT_SECURITY_CONFIG, merged_security_config
from .engine import (
    SecurityOptions,
    SecurityStageResult,
    run_security_stage,
    STAGE_STATUS_DISABLED,
    STAGE_STATUS_OK,
    STAGE_STATUS_UNAVAILABLE,
)
from .policy import (
    PUBLISHABLE_STATUSES,
    STATUS_ALLOW,
    STATUS_ALLOW_WITH_WARNINGS,
    STATUS_BLOCK,
    STATUS_QUARANTINE,
    SecurityDecision,
    evaluate_node,
)
from .verify import verify_security_outputs

__all__ = [
    "DEFAULT_SECURITY_CONFIG",
    "merged_security_config",
    "SecurityOptions",
    "SecurityStageResult",
    "run_security_stage",
    "STAGE_STATUS_DISABLED",
    "STAGE_STATUS_OK",
    "STAGE_STATUS_UNAVAILABLE",
    "PUBLISHABLE_STATUSES",
    "STATUS_ALLOW",
    "STATUS_ALLOW_WITH_WARNINGS",
    "STATUS_BLOCK",
    "STATUS_QUARANTINE",
    "SecurityDecision",
    "evaluate_node",
    "verify_security_outputs",
]
