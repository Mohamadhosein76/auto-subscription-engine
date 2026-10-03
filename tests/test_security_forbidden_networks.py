"""Cloudflare-zero publish invariant (publish-side hardening).

Project rule: Cloudflare must be completely zero — not only as a
dependency/service, but also as the final endpoint network. These tests
pin the guarantee end-to-end (all offline, every network function
injected):

- ASNs 13335 / 209242 are hard-BLOCKed (risk 100,
  cloudflare_network_forbidden);
- an explicit Cloudflare organisation identity is blocked even when the
  ASN is not on the static list (defense-in-depth, precise word-boundary
  match — no weak substring matching);
- ordinary CDN/hosting ASNs are never blocked;
- a node whose ASN cannot be determined is QUARANTINEd, never published;
- blocked Cloudflare nodes reach neither subscription, nor best, nor
  country outputs, and are never selected=true;
- the published metadata records asn/as_name + security metadata for
  blocked nodes without any credential;
- no Cloudflare service/API dependency exists anywhere.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests
import yaml

from auto_subscription_engine.core.models.fingerprint import normalize_config
from auto_subscription_engine.core.protocols import parse_uri
from auto_subscription_engine.core.utils.identity import config_safe_id
from auto_subscription_engine.core.security.asnmap import AsnInfo
from auto_subscription_engine.core.security.config import DEFAULT_SECURITY_CONFIG
from auto_subscription_engine.core.security.engine import (
    STAGE_STATUS_OK,
    SecurityOptions,
    run_security_stage,
)
from auto_subscription_engine.core.security.feedcache import FeedCache, build_record
from auto_subscription_engine.core.security.policy import (
    PUBLISHABLE_STATUSES,
    STATUS_BLOCK,
    NodeSecurityEvidence,
    evaluate_node,
    is_cloudflare_org_name,
)
from auto_subscription_engine.core.security.tlsprobe import (
    EndpointProbe,
    NodeProbeResult,
)
from auto_subscription_engine.core.security.verify import verify_security_outputs

NOW = datetime.now(timezone.utc).replace(microsecond=0)
TESTING_CONFIG = Path(__file__).parent.parent / "config" / "testing.yaml"
REPO_ROOT = Path(__file__).parent.parent

# -- fake roster ---------------------------------------------------------------
# CF1/CF2: endpoints on forbidden Cloudflare ASNs (real Cymru-style names).
# CF3: unknown-but-harmless ASN whose organisation name says Cloudflare.
# OK1/OK2: ordinary hosting/CDN ASNs. UNK: ASN undeterminable.
CF1 = "vless://11111111-2222-3333-4444-555555555551@104.16.132.229:443?security=tls&type=tcp#cf-asn"
CF2 = "vless://11111111-2222-3333-4444-555555555552@172.64.1.1:443?security=tls&type=tcp#cf-spectrum"
CF3 = "trojan://pw@cf-org.example:443?security=tls#cf-org-name"
OK1 = "trojan://pw@cdn.example:443?security=tls#clean-cdn"
OK2 = "vless://11111111-2222-3333-4444-555555555555@8.8.8.8:443?security=tls&type=tcp#clean-hosting"
UNK = "trojan://pw@ghost.example:443?security=tls#asn-unknown"

ALL_URIS = [CF1, CF2, CF3, OK1, OK2, UNK]

RESOLVED_IP = {
    CF1: "104.16.132.229",
    CF2: "172.64.1.1",
    CF3: "198.41.200.10",
    OK1: "93.184.216.34",
    OK2: "8.8.8.8",
    UNK: "7.7.7.7",
}

CYMRU_ASN = {
    "104.16.132.229": (13335, "CLOUDFLARENET - Cloudflare, Inc., US"),
    "172.64.1.1": (209242, "CLOUDFLARESPECTRUM - Cloudflare London, LLC, US"),
    "198.41.200.10": (64512, "Cloudflare, Inc."),
    "93.184.216.34": (64513, "EXAMPLE-HOSTING, US"),
    "8.8.8.8": (15169, "GOOGLE, US"),
    # 7.7.7.7 deliberately absent -> asn None -> RIPEstat fails too
}

FEED_BODIES = {
    "drop.txt": b"# DROP\n203.0.113.0/24 ; S1\n",
    "dropv6.txt": b"# DROPv6\n2001:db8::/32 ; S1\n",
    "asndrop.json": b'{"asn": 64496, "rir": "arin", "cc": "US", "asname": "EVIL-AS"}\n'
    b'{"type": "metadata", "timestamp": 1790689442, "records": 430, "copyright": "(c) 2026 The Spamhaus Project SLU", "terms": "https://www.spamhaus.org/drop/terms/"}\n',
    "ipblocklist_recommended.json": b'[{"ip_address": "5.6.7.8", "malware": "testbot"}]',
}

SYSTEM_DNS = {
    "cf-org.example": ["198.41.200.10"],
    "cdn.example": ["93.184.216.34"],
    "ghost.example": ["7.7.7.7"],
}

DOH_DNS = {
    "cf-org.example": ["198.41.200.10"],
    "cdn.example": ["93.184.216.34"],
    "ghost.example": ["7.7.7.7"],
}


def _feed_downloader(url: str) -> bytes:
    name = url.rsplit("/", 1)[-1]
    return FEED_BODIES[name]


def _cymru_query(ips):
    out = {}
    for ip in ips:
        entry = CYMRU_ASN.get(ip)
        out[ip] = AsnInfo(
            asn=entry[0] if entry else None,
            as_name=entry[1] if entry else None,
            prefix=f"{ip}/24",
            source="cymru_whois",
            looked_up_at=NOW.isoformat(),
        )
    return out


class _OfflineSession:
    """Every RIPEstat fallback attempt fails (offline determinism)."""

    def get(self, *args, **kwargs):
        raise requests.ConnectionError("offline test: no fallback")

    def close(self):
        pass


def _good_probe(config, resolved_ip=None) -> NodeProbeResult:
    return NodeProbeResult(
        core_started=True,
        endpoints=[
            EndpointProbe(endpoint=f"ep{i}", tls_ok=True, status=200,
                          content_ok=True, body_text="ok data", body_size=7)
            for i in range(3)
        ],
    )


class _FakeRunner:
    def probe_node(self, config, resolved_ip=None):
        return _good_probe(config, resolved_ip)

    def cleanup(self):
        pass


def _system_resolver(host):
    return list(SYSTEM_DNS.get(host, []))


def _doh_resolver(host):
    return list(DOH_DNS.get(host, []))


def _sid(uri: str) -> str:
    return config_safe_id(normalize_config(parse_uri(uri)))


@pytest.fixture()
def live_output(tmp_path: Path) -> Path:
    """Fabricate a Task 2 live output directory with correctly joined ids."""
    output = tmp_path / "output"
    (output / "countries").mkdir(parents=True)
    nodes = []
    for index, uri in enumerate(ALL_URIS):
        config = normalize_config(parse_uri(uri))
        nodes.append({
            "safe_id": config_safe_id(config),
            "protocol": config.protocol,
            "status": "live",
            "selected": uri != CF3,  # CF3 was not selected before security
            "country_code": "US",
            "country_name": "United States",
            "resolved_ip": RESOLVED_IP[uri],
            "tcp_latency_ms": 20.0,
            "proxy_latency_ms": 300.0,
            "success_ratio": 1.0,
            "score": 90 - index,
        })
    body = "\n".join(ALL_URIS) + "\n"
    (output / "live_subscription.txt").write_text(body, encoding="utf-8")
    (output / "live_subscription_base64.txt").write_text(
        base64.b64encode(body.encode("utf-8")).decode("ascii") + "\n", encoding="ascii"
    )
    (output / "best.txt").write_text(
        "\n".join(u for u in ALL_URIS if u != CF3) + "\n", encoding="utf-8"
    )
    (output / "countries" / "US.txt").write_text(
        "\n".join(u for u in ALL_URIS if u != CF3) + "\n", encoding="utf-8"
    )
    (output / "live_nodes.json").write_text(
        json.dumps(nodes, indent=2) + "\n", encoding="utf-8"
    )
    stats = {
        "generated_at": NOW.isoformat(timespec="seconds"),
        "pipeline": "live-connectivity",
        "live_total": len(ALL_URIS),
        "live_selected": 5,
        "count_by_country": {"US": 5},
        "count_by_protocol_live": {"trojan": 3, "vless": 3},
        "status": "ok",
    }
    (output / "live_stats.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    return output


def _options(output: Path, tmp_path: Path, **overrides) -> SecurityOptions:
    defaults = dict(
        output_dir=output,
        testing_config_path=TESTING_CONFIG,
        core_paths={},
        security_cache_dir=tmp_path / "data" / "security" / "feeds",
        now=lambda: NOW,
        feed_downloader=_feed_downloader,
        cymru_query=_cymru_query,
        probe_runner=_FakeRunner(),
        system_resolver=_system_resolver,
        doh_resolver=_doh_resolver,
        session=_OfflineSession(),
    )
    defaults.update(overrides)
    return SecurityOptions(**defaults)


def _nodes(output: Path) -> dict:
    return {
        n["safe_id"]: n
        for n in json.loads((output / "live_nodes.json").read_text(encoding="utf-8"))
    }


# ---------------------------------------------------------------------------
# Policy-level: forbidden networks and identities
# ---------------------------------------------------------------------------


def _evidence(**fields) -> NodeSecurityEvidence:
    base = dict(
        probes=NodeProbeResult(
            core_started=True,
            endpoints=[
                EndpointProbe(endpoint="ep", tls_ok=True, status=200,
                              content_ok=True, body_text="ok", body_size=2)
            ],
        ),
        asn=AsnInfo(asn=64513, as_name="EXAMPLE-HOSTING, US"),
        require_asn=True,
    )
    base.update(fields)
    return NodeSecurityEvidence(**base)


def test_asn_13335_is_blocked():
    decision = evaluate_node(_evidence(
        asn=AsnInfo(asn=13335, as_name="CLOUDFLARENET - Cloudflare, Inc., US"),
        cloudflare_network_hit=True,
    ))
    assert decision.status == STATUS_BLOCK
    assert "cloudflare_network_forbidden" in decision.reasons
    assert decision.risk_score == 100
    assert decision.status not in PUBLISHABLE_STATUSES


def test_asn_209242_is_blocked():
    decision = evaluate_node(_evidence(
        asn=AsnInfo(asn=209242, as_name="CLOUDFLARESPECTRUM - Cloudflare London, LLC, US"),
        cloudflare_network_hit=True,
    ))
    assert decision.status == STATUS_BLOCK
    assert "cloudflare_network_forbidden" in decision.reasons
    assert decision.risk_score == 100


def test_cloudflare_org_identity_blocks_unlisted_asn():
    """Defense-in-depth: name says Cloudflare, ASN is not on the list."""
    decision = evaluate_node(_evidence(
        asn=AsnInfo(asn=64512, as_name="Cloudflare, Inc."),
        cloudflare_org_hit=True,
    ))
    assert decision.status == STATUS_BLOCK
    assert "cloudflare_org_identity" in decision.reasons
    assert decision.risk_score == 100


@pytest.mark.parametrize("name", [
    "CLOUDFLARENET",
    "Cloudflare",
    "Cloudflare, Inc.",
    "cloudflare, inc.",
    "  CLOUDFLARE  ",
    "Cloudflare London, LLC",
    "CLOUDFLARESPECTRUM - Cloudflare London, LLC, US",
    "CLOUDFLARENET - Cloudflare, Inc., US",
])
def test_cloudflare_identity_matches_explicit_names(name: str):
    assert is_cloudflare_org_name(name) is True


@pytest.mark.parametrize("name", [
    "AMAZON-02, US",
    "GOOGLE, US",
    "OVH SAS",
    "Hetzner Online GmbH",
    "DigitalOcean, LLC",
    "EXAMPLE-HOSTING, US",
    "Cloudless Hosting Ltd",
    "ACLOUDFLAREIMITATOR",
    "CLOUDFLARELIKE-HOSTING",
    "",
    None,
])
def test_cloudflare_identity_never_false_positives(name):
    """Generic hosts (and concatenated look-alikes) must never match."""
    assert is_cloudflare_org_name(name) is False


def test_normal_hosting_and_cdn_asns_are_not_blocked():
    for asn, name in (
        (15169, "GOOGLE, US"),
        (16509, "AMAZON-02, US"),
        (16276, "OVH SAS"),
        (24940, "Hetzner Online GmbH"),
        (64513, "EXAMPLE-HOSTING, US"),
    ):
        decision = evaluate_node(_evidence(
            asn=AsnInfo(asn=asn, as_name=name),
        ))
        assert decision.status in PUBLISHABLE_STATUSES, (asn, decision)
        assert not any(r.startswith("cloudflare_") for r in decision.reasons)


def test_unknown_asn_is_quarantined_not_published():
    decision = evaluate_node(_evidence(asn=AsnInfo()))
    assert decision.status == "quarantine"
    assert "asn_unknown" in decision.reasons
    assert decision.status not in PUBLISHABLE_STATUSES
    assert not decision.checks_complete


def test_unknown_asn_without_requirement_stays_publishable_with_warning():
    """Documents the knob: require_asn=False keeps the legacy behaviour."""
    decision = evaluate_node(_evidence(asn=AsnInfo(), require_asn=False))
    assert decision.status in PUBLISHABLE_STATUSES
    assert "asn_lookup_unavailable" in decision.warnings


def test_block_is_never_downgraded_by_missing_asn():
    """A forbidden-network BLOCK stands even when the ASN is unknown
    (e.g. cached org identity) - no quarantine downgrade happens."""
    decision = evaluate_node(_evidence(
        asn=AsnInfo(),
        cloudflare_network_hit=True,
    ))
    assert decision.status == STATUS_BLOCK
    assert "cloudflare_network_forbidden" in decision.reasons
    assert "asn_unknown" not in decision.reasons
    decision = evaluate_node(_evidence(
        asn=AsnInfo(),
        cloudflare_org_hit=True,
    ))
    assert decision.status == STATUS_BLOCK
    assert "cloudflare_org_identity" in decision.reasons


def test_forbidden_asns_default_matches_project_policy():
    merged = DEFAULT_SECURITY_CONFIG["policy"]
    assert sorted(merged["forbidden_asns"]) == [13335, 209242]
    assert merged["require_asn_for_publish"] is True


# ---------------------------------------------------------------------------
# Engine-level: blocked Cloudflare nodes cannot reach any public output
# ---------------------------------------------------------------------------


def test_cloudflare_nodes_blocked_everywhere(live_output: Path, tmp_path: Path):
    result = run_security_stage(_options(live_output, tmp_path))
    assert result.status == STAGE_STATUS_OK

    subscription = (live_output / "live_subscription.txt").read_text(encoding="utf-8")
    kept = [line for line in subscription.splitlines() if line.strip()]
    assert kept == [OK1, OK2]

    nodes = _nodes(live_output)

    # ASN 13335 blocked with full security metadata (no credentials).
    node1 = nodes[_sid(CF1)]
    assert node1["security_status"] == STATUS_BLOCK
    assert node1["security_risk_score"] == 100
    assert "cloudflare_network_forbidden" in node1["security_reasons"]
    assert node1["asn"] == 13335
    assert "CLOUDFLARENET" in str(node1["as_name"])
    assert node1["selected"] is False

    # ASN 209242 blocked as well.
    node2 = nodes[_sid(CF2)]
    assert node2["security_status"] == STATUS_BLOCK
    assert node2["security_risk_score"] == 100
    assert "cloudflare_network_forbidden" in node2["security_reasons"]
    assert node2["asn"] == 209242
    assert node2["selected"] is False

    # Cloudflare organisation identity blocked (defense-in-depth).
    node3 = nodes[_sid(CF3)]
    assert node3["security_status"] == STATUS_BLOCK
    assert "cloudflare_org_identity" in node3["security_reasons"]
    assert node3["asn"] == 64512  # not on the static list
    assert node3["selected"] is False

    # Unknown ASN quarantined (never ALLOW), metadata kept transparently.
    node_unk = nodes[_sid(UNK)]
    assert node_unk["security_status"] == "quarantine"
    assert "asn_unknown" in node_unk["security_reasons"]
    assert node_unk["asn"] is None
    assert node_unk["selected"] is False

    # Ordinary hosting/CDN nodes stay publishable.
    assert nodes[_sid(OK1)]["security_status"] in PUBLISHABLE_STATUSES
    assert nodes[_sid(OK2)]["security_status"] in PUBLISHABLE_STATUSES

    # best.txt / countries/ contain neither blocked nor quarantined nodes.
    best = [l for l in (live_output / "best.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
    assert best == [OK1, OK2]
    countries = (live_output / "countries" / "US.txt").read_text(encoding="utf-8")
    assert [l for l in countries.splitlines() if l.strip()] == [OK1, OK2]

    stats = json.loads((live_output / "live_stats.json").read_text(encoding="utf-8"))
    assert stats["cloudflare_nodes_blocked"] == 3
    assert stats["security_blocked"] == 3
    assert stats["security_quarantined"] == 1
    assert stats["security_publishable"] == 2
    assert stats["live_selected"] == 2
    assert stats["live_total"] == 2

    # base64 still consistent with the filtered subscription
    encoded = (live_output / "live_subscription_base64.txt").read_text(encoding="ascii").strip()
    assert base64.b64decode(encoded).decode("utf-8") == subscription


def test_public_output_contains_zero_cloudflare_asn(live_output: Path, tmp_path: Path):
    run_security_stage(_options(live_output, tmp_path))
    nodes = _nodes(live_output)
    publishable = [
        n for n in nodes.values()
        if n.get("security_status") in PUBLISHABLE_STATUSES
    ]
    assert publishable, "sanity: publishable nodes exist"
    for node in publishable:
        assert node.get("asn") not in (13335, 209242, None), node
        assert not is_cloudflare_org_name(node.get("as_name")), node
    for node in nodes.values():
        if node.get("selected"):
            assert node.get("security_status") in PUBLISHABLE_STATUSES
            assert node.get("asn") not in (13335, 209242, None)


def test_blocked_cloudflare_metadata_stays_credential_free(live_output: Path, tmp_path: Path):
    run_security_stage(_options(live_output, tmp_path))
    uuid_re = re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    for name in ("live_nodes.json", "live_stats.json", "security_diagnostics.json"):
        text = (live_output / name).read_text(encoding="utf-8")
        assert not re.search(r"(vless|vmess|trojan|ss|hysteria2|hy2)://", text, re.I), name
        assert not uuid_re.search(text), name
        assert '"password"' not in text and '"original_uri"' not in text, name


def test_rerun_keeps_blocked_cloudflare_exclusion_deterministic(live_output: Path, tmp_path: Path):
    run_security_stage(_options(live_output, tmp_path))
    snapshot = {
        name: (live_output / name).read_bytes()
        for name in ("live_subscription.txt", "live_nodes.json",
                     "live_stats.json", "best.txt", "countries/US.txt")
    }
    # The URIs of blocked nodes left the subscription; the metadata stays
    # carried over verbatim and the counters must not drift.
    second = run_security_stage(_options(live_output, tmp_path))
    assert second.status == STAGE_STATUS_OK
    for name, content in snapshot.items():
        assert (live_output / name).read_bytes() == content, name
    stats = json.loads((live_output / "live_stats.json").read_text(encoding="utf-8"))
    assert stats["cloudflare_nodes_blocked"] == 3


# ---------------------------------------------------------------------------
# Verify-level: the pre-publish gate enforces the invariant
# ---------------------------------------------------------------------------


def test_verify_accepts_cloudflare_free_outputs(live_output: Path, tmp_path: Path):
    run_security_stage(_options(live_output, tmp_path))
    assert verify_security_outputs(live_output, TESTING_CONFIG) == []


def test_verify_flags_selected_node_on_forbidden_asn(live_output: Path, tmp_path: Path):
    run_security_stage(_options(live_output, tmp_path))
    entries = json.loads((live_output / "live_nodes.json").read_text(encoding="utf-8"))
    for entry in entries:
        if entry.get("selected"):
            entry["asn"] = 13335
    (live_output / "live_nodes.json").write_text(
        json.dumps(entries, indent=2), encoding="utf-8"
    )
    problems = verify_security_outputs(live_output, TESTING_CONFIG)
    assert any("forbidden ASN 13335" in p for p in problems)


def test_verify_flags_published_node_without_asn(live_output: Path, tmp_path: Path):
    run_security_stage(_options(live_output, tmp_path))
    entries = json.loads((live_output / "live_nodes.json").read_text(encoding="utf-8"))
    for entry in entries:
        if entry.get("selected"):
            entry["asn"] = None
    (live_output / "live_nodes.json").write_text(
        json.dumps(entries, indent=2), encoding="utf-8"
    )
    problems = verify_security_outputs(live_output, TESTING_CONFIG)
    assert any("no determined ASN" in p for p in problems)


def test_verify_flags_cloudflare_identity_on_published_node(live_output: Path, tmp_path: Path):
    run_security_stage(_options(live_output, tmp_path))
    entries = json.loads((live_output / "live_nodes.json").read_text(encoding="utf-8"))
    for entry in entries:
        if entry.get("selected"):
            entry["as_name"] = "Cloudflare, Inc."
    (live_output / "live_nodes.json").write_text(
        json.dumps(entries, indent=2), encoding="utf-8"
    )
    problems = verify_security_outputs(live_output, TESTING_CONFIG)
    assert any("Cloudflare AS identity" in p for p in problems)


def test_verify_flags_missing_cloudflare_counter(live_output: Path, tmp_path: Path):
    run_security_stage(_options(live_output, tmp_path))
    stats = json.loads((live_output / "live_stats.json").read_text(encoding="utf-8"))
    stats.pop("cloudflare_nodes_blocked")
    (live_output / "live_stats.json").write_text(
        json.dumps(stats, indent=2), encoding="utf-8"
    )
    problems = verify_security_outputs(live_output, TESTING_CONFIG)
    assert any("cloudflare_nodes_blocked" in p for p in problems)


# ---------------------------------------------------------------------------
# No Cloudflare service/API dependency introduced
# ---------------------------------------------------------------------------


def _walk_strings(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _walk_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk_strings(v)
    elif isinstance(value, str):
        yield value


def test_security_config_references_no_cloudflare_service():
    for text in _walk_strings(DEFAULT_SECURITY_CONFIG):
        assert "cloudflare" not in text.lower(), text


def test_asn_detection_sources_unchanged_and_cloudflare_free():
    """ASN facts still come only from Team Cymru / RIPEstat."""
    asn_cfg = DEFAULT_SECURITY_CONFIG["asn"]
    assert asn_cfg["whois_host"] == "whois.cymru.com"
    assert "stat.ripe.net" in asn_cfg["fallback_url"]
    assert DEFAULT_SECURITY_CONFIG["dns"]["doh_url"] == "https://dns.google/resolve"


def test_no_cloudflare_endpoint_in_project_sources():
    """Same pattern the CI guard uses: no cloudflare.* endpoint, no
    cloudflared tunnel reference anywhere in src/ or config/."""
    pattern = re.compile(
        r"([a-z0-9-]+\.)*((trycloudflare|cloudflare)\.[a-z]{2,}|cloudflared)",
        re.IGNORECASE,
    )
    for base in (REPO_ROOT / "src", REPO_ROOT / "config"):
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            assert not pattern.search(text), path


def test_cloudflare_policy_uses_only_asn_metadata():
    """The block decision consumes ASN facts already fetched (Cymru /
    RIPEstat) - it performs no lookup against any Cloudflare service."""
    testing_cfg = yaml.safe_load(TESTING_CONFIG.read_text(encoding="utf-8"))
    policy_cfg = testing_cfg["security"]["policy"]
    assert policy_cfg["forbidden_asns"] == [13335, 209242]
    assert policy_cfg["require_asn_for_publish"] is True
    for url in _walk_strings(testing_cfg["security"]):
        assert "cloudflare" not in url.lower(), url
