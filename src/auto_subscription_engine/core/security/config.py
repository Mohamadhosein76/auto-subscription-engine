"""Security layer configuration defaults (Task 4: Security Hardening).

Every value here is non-sensitive and safe to publish. All network
access is bounded (timeouts, retries, concurrency) and limited to:

- official, free reputation feeds (Spamhaus DROP, Feodo Tracker),
- key-free ASN mapping (Team Cymru, RIPEstat fallback),
- key-free DNS-over-HTTPS (Google Public DNS — deliberately NOT
  Cloudflare, which is banned project-wide),
- small, stable HTTPS integrity endpoints.

Only endpoint data that the engine's own sources already provided is
ever contacted; no network scanning of any kind happens. Credentials
(UUID/password/URI) never leave the process.
"""

from __future__ import annotations

import json

#: Deep-copyable default configuration, merged over by config/testing.yaml.
DEFAULT_SECURITY_CONFIG: dict = {
    # The whole layer can be switched off (not recommended; CI verifies it).
    "enabled": True,
    "feeds": {
        # Official free feeds only. Spamhaus DROP is free for non-commercial
        # use with attribution (kept in feed metadata and README).
        "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
        "spamhaus_dropv6": "https://www.spamhaus.org/drop/dropv6.txt",
        # The legacy asndrop.txt was retired upstream in favour of JSON.
        "spamhaus_asndrop": "https://www.spamhaus.org/drop/asndrop.json",
        # Feodo Tracker "recommended" blocklist = currently active botnet
        # C2 hosts (the aggressive/historical lists are intentionally NOT
        # used: higher false-positive rate). The legacy
        # recommended_ipblocklist.* files were retired upstream.
        "feodo_recommended": (
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
        ),
        # Politeness: at most one download per feed per day. The hourly
        # workflow reuses the persisted cache instead of re-downloading.
        "refresh_interval_hours": 24,
        # A feed older than this is no longer trustworthy: if it cannot be
        # refreshed the whole publish halts (previous output preserved).
        "max_age_hours": 96,
        "timeout_seconds": 20.0,
        "retries": 2,
        "max_bytes": 5 * 1024 * 1024,
    },
    "asn": {
        # Primary: Team Cymru IP-to-ASN bulk whois (one connection for all
        # IPs — polite and fast). Fallback: RIPEstat network-info API.
        "whois_host": "whois.cymru.com",
        "whois_port": 43,
        "fallback_url": "https://stat.ripe.net/data/network-info/data.json",
        "timeout_seconds": 10.0,
        "retries": 1,
        "concurrency": 4,
        # Per-IP cache TTL and hard bound so the file cannot grow forever.
        "cache_ttl_hours": 336,
        "max_cache_entries": 20000,
        "max_lookups_per_run": 5000,
    },
    "dns": {
        # Independent second resolver. Google Public DNS DoH is used
        # deliberately: key-free and NOT Cloudflare (banned project-wide).
        "doh_url": "https://dns.google/resolve",
        "timeout_seconds": 5.0,
        "concurrency": 8,
    },
    "tls": {
        "timeout_seconds": 8.0,
    },
    "content": {
        # HTTPS integrity endpoints: small, stable, independent operators,
        # none served by a Cloudflare edge. At least two independent
        # providers are required by policy; three are configured so one
        # flaky endpoint cannot wrongly quarantine a node.
        "endpoints": [
            {
                "url": "https://www.google.com/robots.txt",
                "expect_status": 200,
                "expect_substring": "User-agent",
            },
            {
                "url": "https://www.wikipedia.org",
                "expect_status": 200,
                "expect_substring": "Wikipedia",
            },
            {
                "url": "https://example.com/",
                "expect_status": 200,
                "expect_substring": "Example Domain",
            },
        ],
        "timeout_seconds": 8.0,
        "max_body_bytes": 65536,
        # Independent endpoints that must fail integrity before the node
        # is treated as a content-integrity anomaly (retry-once included).
        "failure_threshold": 2,
    },
    "probe": {
        # LIVE nodes only are probed (already a small set: ~tens).
        "concurrency": 8,
        "startup_timeout_seconds": 5.0,
    },
    "policy": {
        # ASN concentration is a *diversity* signal, not malice: cap the
        # number of published nodes per announcing ASN. Datacenter/cloud
        # ASNs are never blocked for being datacenters.
        "max_nodes_per_asn": 10,
        # When probes are inconclusive (e.g. exit blocks every integrity
        # endpoint) the node is published only with a visible warning and
        # security_checks_complete=false. This stays honest: incomplete
        # checks are never reported as "safe".
        "quarantine_on_incomplete": False,
        # Project invariant: Cloudflare must be completely zero - not
        # only as a dependency/service, but also as the final endpoint
        # network. Endpoints announced by these Cloudflare-owned ASNs
        # are hard-blocked (risk score 100, reason
        # cloudflare_network_forbidden) and can never be published.
        "forbidden_asns": [13335, 209242],
        # Publishing requires a determined ASN: an endpoint whose ASN
        # cannot be established (Team Cymru + RIPEstat both failed)
        # cannot be proven non-Cloudflare and is therefore QUARANTINEd,
        # never published. Defense-in-depth additionally blocks any AS
        # whose organisation name explicitly matches Cloudflare (see
        # policy.is_cloudflare_org_name) even when its ASN is not
        # listed above.
        "require_asn_for_publish": True,
    },
    # Security publishing guard: if fewer publishable nodes than this
    # survive the security filtering, publishing is skipped entirely and
    # the previous healthy subscription is preserved.
    "min_publishable_nodes": 5,
}


def merged_security_config(overrides: dict | None) -> dict:
    """Deep-merge ``overrides`` (from testing.yaml) over the defaults."""
    merged = json.loads(json.dumps(DEFAULT_SECURITY_CONFIG))
    if not overrides:
        return merged
    if not isinstance(overrides, dict):
        raise ValueError("security config section must be a mapping")
    for section, values in overrides.items():
        if isinstance(values, dict) and isinstance(merged.get(section), dict):
            merged[section].update(values)
        else:
            merged[section] = values
    return merged
