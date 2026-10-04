"""Task 4 tests: the security stage end-to-end (fully offline).

Fabricates a Task 2 live output directory, injects fake feeds, ASN
answers, DNS resolvers and probe results, then verifies the rewritten
outputs: only ALLOW / ALLOW_WITH_WARNINGS nodes survive, statistics are
complete, metadata stays credential-free, and required-feed outages
preserve the previous outputs untouched.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from auto_subscription_engine.core.models.fingerprint import normalize_config
from auto_subscription_engine.core.protocols import parse_uri
from auto_subscription_engine.core.utils.identity import config_safe_id
from auto_subscription_engine.core.security.asnmap import AsnInfo
from auto_subscription_engine.core.security.engine import (
    STAGE_STATUS_DISABLED,
    STAGE_STATUS_OK,
    STAGE_STATUS_UNAVAILABLE,
    SecurityOptions,
    run_security_stage,
)
from auto_subscription_engine.core.security.feedcache import build_record
from auto_subscription_engine.core.security.feeds import FeedUnavailableError
from auto_subscription_engine.core.security.tlsprobe import (
    EndpointProbe,
    NodeProbeResult,
)

NOW = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)
TESTING_CONFIG = Path(__file__).parent.parent / "config" / "testing.yaml"

# Node roster (all fake; nothing here is contacted).
N0 = "vless://11111111-2222-3333-4444-555555555555@93.184.216.34:443?security=tls&type=tcp#clean-0"
N1 = "vless://11111111-2222-3333-4444-555555555556@1.2.3.4:443?security=tls&type=tcp#dropped"
N2 = "vless://11111111-2222-3333-4444-555555555557@5.6.7.8:443?security=tls&type=tcp#feodo"
N3 = "vless://11111111-2222-3333-4444-555555555558@9.9.9.9:443?security=tls&type=tcp#asndropped"
N4 = "trojan://pw@evil-host.example:443?security=tls#dns-private"
N5 = "trojan://pw@rebind-host.example:443?security=tls#dns-rebind"
N6 = "trojan://pw@cdn-host.example:443?security=tls#benign-mismatch"
N7 = "trojan://pw@plain-host.example:443?security=tls#clean-1"

ALL_URIS = [N0, N1, N2, N3, N4, N5, N6, N7]

RESOLVED_IP = {
    N0: "93.184.216.34",
    N1: "1.2.3.4",
    N2: "5.6.7.8",
    N3: "9.9.9.9",
    N4: "10.9.9.9",
    N5: "6.6.6.6",
    N6: "8.8.8.8",
    N7: "7.7.7.7",
}

FEED_BODIES = {
    "drop.txt": b"# DROP\n1.2.3.0/24 ; S1\n",
    "dropv6.txt": b"# DROPv6\n2001:db8::/32 ; S1\n",
    "asndrop.json": b'{"asn": 64496, "rir": "arin", "cc": "US", "asname": "EVIL-AS"}\n'
    b'{"type": "metadata", "timestamp": 1790689442, "records": 430, "copyright": "(c) 2026 The Spamhaus Project SLU", "terms": "https://www.spamhaus.org/drop/terms/"}\n',
    "ipblocklist_recommended.json": b'[{"ip_address": "5.6.7.8", "malware": "testbot"}]',
}

CYMRU_ASN = {
    "93.184.216.34": 64512,
    "1.2.3.4": 64512,
    "5.6.7.8": 64512,
    "9.9.9.9": 64496,  # announced by the ASN-DROP-listed AS
    "10.9.9.9": 64512,
    "6.6.6.6": 64512,
    "8.8.8.8": 64512,
    "7.7.7.7": 64512,
}

SYSTEM_DNS = {
    "evil-host.example": ["10.9.9.9"],       # private answer -> BLOCK
    "rebind-host.example": ["6.6.6.6"],      # public...
    "cdn-host.example": ["8.8.8.8"],         # benign mismatch vs DoH
    "plain-host.example": ["7.7.7.7"],
}

DOH_DNS = {
    "evil-host.example": ["93.184.216.34"],
    "rebind-host.example": ["192.168.1.1"],  # ...private -> rebinding BLOCK
    "cdn-host.example": ["8.8.4.4"],
    "plain-host.example": ["7.7.7.7"],
}


def _feed_downloader(url: str) -> bytes:
    name = url.rsplit("/", 1)[-1]
    return FEED_BODIES[name]


def _cymru_query(ips):
    out = {}
    for ip in ips:
        out[ip] = AsnInfo(
            asn=CYMRU_ASN.get(ip),
            as_name="EXAMPLE-HOSTING, US",
            prefix=f"{ip}/24" if ip in CYMRU_ASN else None,
            source="cymru_whois",
            looked_up_at=NOW.isoformat(),
        )
    return out


def _good_probe(config, resolved_ip=None) -> NodeProbeResult:
    return NodeProbeResult(
        core_started=True,
        endpoints=[
            EndpointProbe(endpoint=f"ep{i}", tls_ok=True, status=200, content_ok=True,
                          body_text="ok data", body_size=7)
            for i in range(3)
        ],
    )


def _system_resolver(host):
    return list(SYSTEM_DNS.get(host, []))


def _doh_resolver(host):
    value = DOH_DNS.get(host, [])
    return list(value) if value else []


@pytest.fixture()
def live_output(tmp_path: Path) -> Path:
    """Fabricate a Task 2 live output directory with correctly joined ids."""
    output = tmp_path / "output"
    (output / "countries").mkdir(parents=True)
    nodes = []
    uris = []
    for index, uri in enumerate(ALL_URIS):
        config = normalize_config(parse_uri(uri))
        safe_id = config_safe_id(config)
        uris.append(uri)
        resolved = RESOLVED_IP[uri]
        nodes.append({
            "safe_id": safe_id,
            "protocol": config.protocol,
            "status": "live",
            "selected": index < 6,  # best = first six (pre-security)
            "country_code": "US",
            "country_name": "United States",
            "resolved_ip": resolved,
            "tcp_latency_ms": 20.0,
            "proxy_latency_ms": 300.0,
            "success_ratio": 1.0,
            "score": 90 - index,
        })
    body = "\n".join(uris) + "\n"
    (output / "live_subscription.txt").write_text(body, encoding="utf-8")
    (output / "live_subscription_base64.txt").write_text(
        base64.b64encode(body.encode("utf-8")).decode("ascii") + "\n", encoding="ascii"
    )
    (output / "best.txt").write_text("\n".join(uris[:6]) + "\n", encoding="utf-8")
    (output / "countries" / "US.txt").write_text("\n".join(uris[:6]) + "\n", encoding="utf-8")
    (output / "live_nodes.json").write_text(
        json.dumps(nodes, indent=2) + "\n", encoding="utf-8"
    )
    stats = {
        "generated_at": NOW.isoformat(timespec="seconds"),
        "pipeline": "live-connectivity",
        "configs_received": 100,
        "final_configs": 80,
        "candidates_sampled": 50,
        "tcp_tested": 50,
        "tcp_passed": 20,
        "proxy_tested": 10,
        "proxy_live": len(uris),
        "live_total": len(uris),
        "live_selected": 6,
        "count_by_country": {"US": 6},
        "count_by_protocol_live": {"trojan": 4, "vless": 2},
        "runtime_seconds": 60.0,
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
    )
    defaults.update(overrides)
    return SecurityOptions(**defaults)


class _FakeRunner:
    """Probe runner stub returning healthy endpoints for every node."""

    def __init__(self, result_factory=None):
        self._factory = result_factory or _good_probe

    def probe_node(self, config, resolved_ip=None):
        return self._factory(config, resolved_ip)

    def cleanup(self):
        pass


def _read(output: Path, name: str):
    return json.loads((output / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# End-to-end filtering
# ---------------------------------------------------------------------------


def test_security_stage_filters_and_enriches(live_output: Path, tmp_path: Path):
    result = run_security_stage(_options(live_output, tmp_path))
    assert result.status == STAGE_STATUS_OK

    subscription = (live_output / "live_subscription.txt").read_text(encoding="utf-8")
    kept = [line for line in subscription.splitlines() if line.strip()]
    # N1 (DROP), N2 (Feodo), N3 (ASN-DROP), N4 (private DNS), N5 (rebinding)
    # must be gone; N0, N6 (benign mismatch warning), N7 stay.
    assert kept == [N0, N6, N7]

    nodes = {n["safe_id"]: n for n in _read(live_output, "live_nodes.json")}
    by_uri_subscription = set(kept)

    # blocked/quarantined nodes keep metadata transparency...
    assert any(n["security_status"] == "block" for n in nodes.values())
    # ...but never appear in the subscription
    import hashlib

    for uri in (N1, N2, N3, N4, N5):
        sid = config_safe_id(normalize_config(parse_uri(uri)))
        assert sid in nodes
        assert nodes[sid]["security_status"] in ("block", "quarantine")

    stats = _read(live_output, "live_stats.json")
    assert stats["security_checked"] == 8
    assert stats["security_blocked"] == 5
    assert stats["security_publishable"] == 3
    assert stats["live_total"] == 3  # publishable set
    assert stats["pre_security_live_total"] == 8
    assert stats["spamhaus_drop_hits"] == 1
    assert stats["spamhaus_asndrop_hits"] == 1
    assert stats["feodo_hits"] == 1
    assert stats["dns_anomalies"] == 2  # private answer + rebinding
    assert stats["unique_asns"] == 2
    assert stats["security_feed_status"] == "fresh"
    # best = pre-security selected (N0..N5) intersected with publishable
    # (N0, N6, N7) = N0 only; N6/N7 were not selected before security.
    assert stats["count_by_country"] == {"US": 1}
    assert stats["live_selected"] == 1

    # benign mismatch node is ALLOW_WITH_WARNINGS and published
    sid6 = config_safe_id(normalize_config(parse_uri(N6)))
    assert nodes[sid6]["security_status"] == "allow_with_warnings"
    assert nodes[sid6]["dns_status"] == "public_mismatch"

    # security metadata schema on every node
    for node in nodes.values():
        for key in (
            "asn", "as_name", "prefix", "reputation_hits", "dns_status",
            "tls_status", "content_integrity_status", "security_status",
            "security_risk_score", "security_checks_complete",
        ):
            assert key in node, key

    # base64 stays consistent with the filtered subscription
    encoded = (live_output / "live_subscription_base64.txt").read_text(encoding="ascii").strip()
    assert base64.b64decode(encoded).decode("utf-8") == subscription

    # countries rewritten from the filtered selected set
    assert (live_output / "countries" / "US.txt").read_text(encoding="utf-8") == N0 + "\n"


def test_published_metadata_stays_credential_free(live_output: Path, tmp_path: Path):
    run_security_stage(_options(live_output, tmp_path))
    import re

    uuid_re = re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    for name in ("live_nodes.json", "live_stats.json", "security_diagnostics.json"):
        text = (live_output / name).read_text(encoding="utf-8")
        assert not re.search(r"(vless|vmess|trojan|ss|hysteria2)://", text, re.I), name
        assert not uuid_re.search(text), name
        assert '"password"' not in text and '"identity"' not in text, name


def test_diagnostics_contain_safe_identifiers_only(live_output: Path, tmp_path: Path):
    run_security_stage(_options(live_output, tmp_path))
    diag = _read(live_output, "security_diagnostics.json")
    assert diag["note"].startswith("credential-free")
    assert len(diag["nodes"]) == 8
    for node in diag["nodes"]:
        assert set(node) <= {
            "safe_id", "protocol", "resolved_ip", "reputation_hits", "dns",
            "tls_error_categories", "content_failures", "certs", "asn",
            "asn_diversity_excluded", "decision",
        }
        assert "uri" not in node and "original_uri" not in node


def test_security_stage_is_deterministic(live_output: Path, tmp_path: Path):
    first = run_security_stage(_options(live_output, tmp_path))
    snapshot = {
        name: (live_output / name).read_bytes()
        for name in ("live_subscription.txt", "live_nodes.json", "live_stats.json",
                     "best.txt", "countries/US.txt")
    }
    # rerun on the *already filtered* outputs - stable by design
    second = run_security_stage(_options(live_output, tmp_path))
    for name, content in snapshot.items():
        assert (live_output / name).read_bytes() == content, name
    assert first.publishable_total == second.publishable_total


# ---------------------------------------------------------------------------
# ASN diversity cap
# ---------------------------------------------------------------------------


def test_asn_concentration_cap(tmp_path: Path):
    """12 nodes on one ASN: only max_nodes_per_asn=10 stay published."""
    output = tmp_path / "output"
    (output / "countries").mkdir(parents=True)
    uris = []
    nodes = []
    for index in range(12):
        uri = (
            f"vless://11111111-2222-3333-4444-5555555555{index:02d}"
            f"@93.184.216.{index + 10}:443?security=tls&type=tcp#n{index}"
        )
        config = normalize_config(parse_uri(uri))
        uris.append(uri)
        nodes.append({
            "safe_id": config_safe_id(config),
            "protocol": "vless",
            "status": "live",
            "selected": True,
            "country_code": "US",
            "country_name": "United States",
            "resolved_ip": f"93.184.216.{index + 10}",
            "tcp_latency_ms": 20.0, "proxy_latency_ms": 300.0,
            "success_ratio": 1.0, "score": 90 - index,
        })
    body = "\n".join(uris) + "\n"
    (output / "live_subscription.txt").write_text(body, encoding="utf-8")
    (output / "live_subscription_base64.txt").write_text(
        base64.b64encode(body.encode("utf-8")).decode("ascii") + "\n", encoding="ascii")
    (output / "best.txt").write_text(body, encoding="utf-8")
    (output / "live_nodes.json").write_text(json.dumps(nodes, indent=2) + "\n", encoding="utf-8")
    (output / "live_stats.json").write_text(json.dumps({
        "live_total": 12, "live_selected": 12, "count_by_country": {"US": 12},
        "status": "ok",
    }) + "\n", encoding="utf-8")

    # every node maps to the same ASN -> cap 10 keeps the top 10
    single_asn_query = lambda ips: {
        ip: AsnInfo(asn=64512, as_name="SAME-AS, US", source="cymru_whois",
                    looked_up_at=NOW.isoformat())
        for ip in ips
    }
    result = run_security_stage(_options(output, tmp_path, cymru_query=single_asn_query))
    assert result.status == STAGE_STATUS_OK
    kept = [l for l in (output / "live_subscription.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(kept) == 10
    nodes_after = {n["safe_id"]: n for n in _read(output, "live_nodes.json")}
    excluded = [n for n in nodes_after.values() if n.get("asn_diversity_excluded")]
    assert len(excluded) == 2
    # excluded nodes are still policy-clean (diversity, not malice)
    assert all(n["security_status"] in ("allow", "allow_with_warnings") for n in excluded)
    assert _read(output, "live_stats.json")["security_publishable"] == 10


def test_generic_datacenter_asn_is_never_blocked(live_output: Path, tmp_path: Path):
    """Hosting ASNs (AWS/Google-like) never cause BLOCK/QUARANTINE."""
    cloud_query = lambda ips: {
        ip: AsnInfo(asn=16509, as_name="AMAZON-02, US", source="cymru_whois",
                    looked_up_at=NOW.isoformat())
        for ip in ips
    }
    run_security_stage(_options(live_output, tmp_path, cymru_query=cloud_query))
    nodes = {n["safe_id"]: n for n in _read(live_output, "live_nodes.json")}
    # N0, N3, N6, N7 carry no reputation evidence; with a datacenter ASN
    # they must remain publishable (hosting alone is never malice).
    for uri in (N0, N3, N6, N7):
        node = nodes[config_safe_id(normalize_config(parse_uri(uri)))]
        assert node["reputation_hits"] == []
        assert node["security_status"] in ("allow", "allow_with_warnings")


# ---------------------------------------------------------------------------
# Required-feed outage preserves previous outputs
# ---------------------------------------------------------------------------


def test_feed_outage_preserves_outputs_untouched(live_output: Path, tmp_path: Path):
    before = {
        p.relative_to(live_output).as_posix(): p.read_bytes()
        for p in sorted(live_output.rglob("*")) if p.is_file()
    }

    def _failing(url):
        raise ConnectionError("reputation feeds unreachable")

    result = run_security_stage(_options(
        live_output, tmp_path, feed_downloader=_failing,
    ))
    assert result.status == STAGE_STATUS_UNAVAILABLE
    assert "unavailable" in (result.reason or "")

    after = {
        p.relative_to(live_output).as_posix(): p.read_bytes()
        for p in sorted(live_output.rglob("*")) if p.is_file()
    }
    # every pre-existing file byte-identical (only diagnostics may be new)
    for name, content in before.items():
        assert after.get(name) == content, name
    assert "security_diagnostics.json" in after
    diag = _read(live_output, "security_diagnostics.json")
    assert diag["stage_status"] == STAGE_STATUS_UNAVAILABLE


def test_stale_but_usable_cache_serves_on_outage(live_output: Path, tmp_path: Path):
    cache_dir = tmp_path / "data" / "security" / "feeds"
    cache_dir.mkdir(parents=True)
    from auto_subscription_engine.core.security.feedcache import FeedCache

    cache = FeedCache(cache_dir)
    old = NOW - timedelta(hours=48)
    for source, name, entries in (
        ("spamhaus_drop", "drop.txt", ["1.2.3.0/24"]),
        ("spamhaus_dropv6", "dropv6.txt", ["2001:db8::/32"]),
        ("spamhaus_asndrop", "asndrop.json", [64496]),
        ("feodo_recommended", "ipblocklist_recommended.json", ["5.6.7.8"]),
    ):
        cache.save(build_record(
            source, f"https://feeds.example/{name}", entries, FEED_BODIES[name],
            refresh_interval_hours=24, max_age_hours=96, now=old,
        ))

    def _failing(url):
        raise ConnectionError("still unreachable")

    result = run_security_stage(_options(live_output, tmp_path, feed_downloader=_failing))
    assert result.status == STAGE_STATUS_OK
    stats = _read(live_output, "live_stats.json")
    assert stats["security_feed_status"] == "cached"
    # cached feeds still protect: the DROP node is filtered
    kept = (live_output / "live_subscription.txt").read_text(encoding="utf-8")
    assert N1 not in kept


def test_disabled_security_layer_keeps_outputs(live_output: Path, tmp_path: Path):
    config_path = tmp_path / "testing.yaml"
    config_path.write_text("security:\n  enabled: false\n", encoding="utf-8")
    before = (live_output / "live_subscription.txt").read_bytes()
    result = run_security_stage(_options(
        live_output, tmp_path, testing_config_path=config_path,
    ))
    assert result.status == STAGE_STATUS_DISABLED
    assert (live_output / "live_subscription.txt").read_bytes() == before


# ---------------------------------------------------------------------------
# Incomplete probe handling
# ---------------------------------------------------------------------------


def test_inconclusive_probes_publish_with_incomplete_flag(live_output: Path, tmp_path: Path):
    def _dead_probes(config, resolved_ip=None):
        return NodeProbeResult(endpoints=[
            EndpointProbe(endpoint=f"ep{i}", tls_ok=False, inconclusive=True,
                          tls_error="probe_timeout")
            for i in range(3)
        ])

    result = run_security_stage(_options(
        live_output, tmp_path, probe_runner=_FakeRunner(_dead_probes),
    ))
    assert result.status == STAGE_STATUS_OK
    nodes = {n["safe_id"]: n for n in _read(live_output, "live_nodes.json")}
    clean = nodes[config_safe_id(normalize_config(parse_uri(N0)))]
    assert clean["security_checks_complete"] is False
    assert clean["tls_status"] == "inconclusive"
    assert clean["security_status"] == "allow_with_warnings"
    kept = (live_output / "live_subscription.txt").read_text(encoding="utf-8")
    assert N0 in kept  # incomplete is never reported as "safe", but honest
    assert _read(live_output, "live_stats.json")["tls_anomalies"] == 0


def test_cert_failure_on_all_endpoints_quarantines_node(live_output: Path, tmp_path: Path):
    def _mitm_probes(config, resolved_ip=None):
        return NodeProbeResult(endpoints=[
            EndpointProbe(endpoint=f"ep{i}", tls_ok=False, tls_error="untrusted_issuer")
            for i in range(3)
        ])

    run_security_stage(_options(live_output, tmp_path, probe_runner=_FakeRunner(_mitm_probes)))
    kept = (live_output / "live_subscription.txt").read_text(encoding="utf-8")
    assert N0 not in kept  # TLS interception evidence -> not published
    nodes = {n["safe_id"]: n for n in _read(live_output, "live_nodes.json")}
    assert nodes[config_safe_id(normalize_config(parse_uri(N0)))]["security_status"] == "quarantine"
    assert _read(live_output, "live_stats.json")["tls_anomalies"] == 8


def test_missing_core_leaves_checks_incomplete_but_honest(live_output: Path, tmp_path: Path):
    result = run_security_stage(_options(live_output, tmp_path, probe_runner=None))
    assert result.status == STAGE_STATUS_OK
    nodes = {n["safe_id"]: n for n in _read(live_output, "live_nodes.json")}
    clean = nodes[config_safe_id(normalize_config(parse_uri(N0)))]
    assert clean["security_checks_complete"] is False
    # "incomplete" (no probe ran) or "inconclusive" (probe hit a dead
    # endpoint and the OS answered timeout instead of refused — Windows
    # network stacks vary). Both are honest non-pass outcomes.
    assert clean["tls_status"] in ("incomplete", "inconclusive")
