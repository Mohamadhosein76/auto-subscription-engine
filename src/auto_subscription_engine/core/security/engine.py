"""Security Deep Check orchestrator (Task 4).

Runs *after* the real connectivity pipeline and *before* the guarded
publish — exclusively on the (small) set of LIVE nodes:

1. refresh reputation feeds (rate-guarded, persistent cache; a required
   feed being unavailable halts the run — the previous healthy
   subscription is kept, unchecked nodes are never published);
2. DNS security checks (system vs independent DoH, bogon/rebinding);
3. reputation checks (Spamhaus DROP/DROPv6 on the endpoint IP,
   ASN-DROP on the announcing ASN, Feodo active C2 IPs);
4. ASN enrichment (Team Cymru bulk, RIPEstat fallback, per-IP cache);
5. TLS deep check + HTTPS content integrity probes *through the proxy*
   (pinned core, full certificate verification, no bypasses);
6. deterministic policy decision per node (ALLOW / ALLOW_WITH_WARNINGS
   / QUARANTINE / BLOCK) with a deterministic risk score;
7. ASN concentration cap on the publishable ranking (diversity, not
   malice: datacenter ASNs are ordinary);
8. rewrite of the live outputs so that **only** ALLOW /
   ALLOW_WITH_WARNINGS nodes remain in subscription/base64/best and
   the country files, with security metadata and statistics added.

The stage is idempotent, bounded (timeouts + concurrency everywhere)
and completely offline-testable (every network function is injectable).
"""

from __future__ import annotations

import base64
import json
import logging
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import requests

from ..models import ParseError, ParsedConfig, UnknownProtocolError
from ..models.fingerprint import normalize_config
from ..protocols import parse_uri
from ..utils.identity import config_safe_id
from .asnmap import AsnCache, AsnInfo, resolve_asn_map
from .config import merged_security_config
from .dnscheck import DnsEvidence, evaluate_host, is_ip_literal
from .feeds import (
    FeedUnavailableError,
    FeedView,
    build_feed_view,
    refresh_feeds,
    ip_in_drop_networks,
)
from .feedcache import FeedCache, utc_now
from .policy import (
    PUBLISHABLE_STATUSES,
    STATUS_BLOCK,
    STATUS_QUARANTINE,
    SecurityDecision,
    evaluate_node,
    is_cloudflare_org_name,
    summarize_decisions,
)
from ..clients.install import verified_core_paths
from .tlsprobe import NodeProbeResult, SecurityProbeRunner

logger = logging.getLogger(__name__)

STAGE_STATUS_OK = "ok"
STAGE_STATUS_UNAVAILABLE = "security_data_unavailable"
STAGE_STATUS_DISABLED = "disabled"

SECURITY_NODE_KEYS = (
    "asn",
    "as_name",
    "prefix",
    "reputation_hits",
    "dns_status",
    "tls_status",
    "content_integrity_status",
    "security_status",
    "security_risk_score",
    "security_reasons",
    "security_checks_complete",
)


@dataclass
class SecurityOptions:
    """Inputs for one security stage run (paths + injected dependencies)."""

    output_dir: Path
    testing_config_path: Path
    core_dir: Path = Path(".core-bin")
    core_paths: dict[str, Path] | None = None
    security_cache_dir: Path | None = None
    #: None = run the real network calls (CI); tests inject fakes.
    session: requests.Session | None = None
    #: Deterministic clock hook for tests (callable returning datetime).
    now: Callable | None = None
    feed_downloader: Callable | None = None  # url -> bytes
    cymru_query: Callable | None = None      # ips -> dict[ip, AsnInfo]
    probe_runner: object | None = None       # SecurityProbeRunner-like
    system_resolver: Callable | None = None  # host -> [ip]
    doh_resolver: Callable | None = None     # host -> [ip] | None


@dataclass
class SecurityStageResult:
    """Credential-free outcome of one security stage run."""

    status: str = STAGE_STATUS_OK
    reason: str | None = None
    live_total: int = 0
    publishable_total: int = 0
    selected_total: int = 0
    feed_statuses: dict = field(default_factory=dict)
    feed_age_hours: float | None = None
    stats_updates: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Data loading / joining
# ---------------------------------------------------------------------------


def _load_live_outputs(output_dir: Path) -> tuple[list[str], list[dict], dict]:
    """Read (subscription lines, live_nodes entries, stats) from output/."""
    output_dir = Path(output_dir)
    uris = [
        line for line in
        (output_dir / "live_subscription.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    nodes = json.loads((output_dir / "live_nodes.json").read_text(encoding="utf-8"))
    stats = json.loads((output_dir / "live_stats.json").read_text(encoding="utf-8"))
    return uris, nodes, stats


@dataclass
class _NodeBundle:
    """Internal join of one node's URI, parsed config and metadata entry."""

    uri: str
    config: ParsedConfig | None
    safe_id: str
    entry: dict
    resolved_ip: str | None
    parse_failed: bool = False


def _join_nodes(uris: list[str], node_entries: list[dict]) -> list[_NodeBundle]:
    """Join subscription URIs with live_nodes.json entries via safe_id.

    live_nodes.json contains no URI (by design), so the join key is the
    deterministic ``safe_id``. Metadata entries without a matching URI
    (or vice versa) are kept but marked — they can never be published.
    """
    entries_by_id = {}
    for entry in node_entries:
        if isinstance(entry, dict) and entry.get("safe_id"):
            entries_by_id[str(entry["safe_id"])] = entry

    bundles: list[_NodeBundle] = []
    seen_ids: set[str] = set()
    unparsed_index = 0
    for uri in uris:
        try:
            config = normalize_config(parse_uri(uri))
        except (ParseError, UnknownProtocolError, ValueError):
            unparsed_index += 1
            fallback = _NodeBundle(
                uri=uri, config=None, safe_id=f"unparsed:{unparsed_index}", entry={},
                resolved_ip=None, parse_failed=True,
            )
            bundles.append(fallback)
            continue
        safe_id = config_safe_id(config)
        entry = entries_by_id.get(safe_id, {})
        seen_ids.add(safe_id)
        bundles.append(_NodeBundle(
            uri=uri,
            config=config,
            safe_id=safe_id,
            entry=entry,
            resolved_ip=entry.get("resolved_ip"),
        ))

    # Metadata entries with no subscription URI: impossible in a healthy
    # pipeline; kept out of publishing but recorded in metadata updates.
    for safe_id, entry in entries_by_id.items():
        if safe_id not in seen_ids:
            bundles.append(_NodeBundle(
                uri="", config=None, safe_id=safe_id, entry=entry,
                resolved_ip=entry.get("resolved_ip"),
            ))
    return bundles


def _endpoint_ip(bundle: _NodeBundle, dns_evidence: DnsEvidence | None) -> str | None:
    """The public endpoint IP used for reputation and ASN lookups."""
    if bundle.resolved_ip:
        return bundle.resolved_ip
    if dns_evidence is not None:
        for ip in dns_evidence.resolved_ips:
            return ip
    if bundle.config is not None and bundle.config.host and is_ip_literal(bundle.config.host):
        return bundle.config.host
    return None


# ---------------------------------------------------------------------------
# Stage entry point
# ---------------------------------------------------------------------------


def run_security_stage(options: SecurityOptions) -> SecurityStageResult:
    """Execute the full security stage and rewrite the live outputs.

    Contract with the publisher: when ``status`` is not ``ok`` the live
    outputs are untouched and publishing must be skipped (the previous
    healthy public tree stays in place).
    """
    now_fn = options.now or utc_now
    testing_full = _load_testing_file(options.testing_config_path)
    security_cfg = merged_security_config(
        testing_full.get("security") if isinstance(testing_full, dict) else {}
    )
    core_paths = dict(options.core_paths or verified_core_paths(options.core_dir, testing_full))

    result = SecurityStageResult()
    if not security_cfg.get("enabled", True):
        result.status = STAGE_STATUS_DISABLED
        result.reason = "security layer disabled by configuration"
        return result

    output_dir = Path(options.output_dir)
    uris, node_entries, stats = _load_live_outputs(output_dir)
    bundles = _join_nodes(uris, node_entries)
    live_total = len(uris)
    result.live_total = live_total

    # -- 1. reputation feeds (required; may halt the run) -------------------
    feeds_dir = Path(options.security_cache_dir) if options.security_cache_dir \
        else output_dir.parent / "data" / "security" / "feeds"
    cache = FeedCache(feeds_dir)
    try:
        records, feed_statuses = refresh_feeds(
            security_cfg["feeds"],
            cache,
            now=now_fn(),
            session=options.session,
            downloader=options.feed_downloader,
        )
    except FeedUnavailableError as exc:
        result.status = STAGE_STATUS_UNAVAILABLE
        result.reason = str(exc)
        _write_unavailable_diagnostics(output_dir, str(exc), now_fn())
        logger.error("security stage halted: %s", exc)
        return result
    feed_view = build_feed_view(records)

    ages = [record.age_hours(now_fn()) for record in records.values()]
    result.feed_statuses = feed_statuses
    result.feed_age_hours = round(max(ages), 1) if ages else None

    # -- 2. DNS security checks ----------------------------------------------
    dns_map: dict[str, DnsEvidence] = {}
    hosts = [
        bundle.config.host for bundle in bundles
        if bundle.config is not None and bundle.config.host
        and not is_ip_literal(bundle.config.host)
    ]
    for bundle in bundles:
        if bundle.parse_failed:
            continue
        key = bundle.safe_id
        if bundle.config is None:
            continue
        host = bundle.config.host or ""
        if is_ip_literal(host):
            dns_map[key] = evaluate_host(
                host,
                dns_cfg=security_cfg["dns"],
                system_resolver=options.system_resolver,
                doh_resolver=options.doh_resolver,
            )
    if hosts:
        from .dnscheck import evaluate_hosts

        dns_host_map = evaluate_hosts(
            hosts,
            dns_cfg=security_cfg["dns"],
            session=options.session,
            system_resolver=options.system_resolver,
            doh_resolver=options.doh_resolver,
        )
        for bundle in bundles:
            if bundle.config is None:
                continue
            host = bundle.config.host or ""
            if host in dns_host_map:
                dns_map[bundle.safe_id] = dns_host_map[host]

    # -- 3./4. endpoint IPs, reputation and ASN enrichment --------------------
    evidence_ip: dict[str, str | None] = {}
    for bundle in bundles:
        if bundle.parse_failed:
            evidence_ip[bundle.safe_id] = None
            continue
        evidence_ip[bundle.safe_id] = _endpoint_ip(bundle, dns_map.get(bundle.safe_id))

    all_ips = sorted({ip for ip in evidence_ip.values() if ip})
    asn_cfg = security_cfg["asn"]
    asn_cache_path = feeds_dir.parent / "asn_cache.json"
    asn_map, asn_complete = resolve_asn_map(
        all_ips,
        asn_cfg,
        AsnCache(asn_cache_path),
        now=now_fn(),
        session=options.session,
        whois_query=options.cymru_query,
    )

    # -- 5. TLS + content probes (LIVE nodes only, bounded) --------------------
    probes: dict[str, NodeProbeResult] = {}
    probe_runner_ready = options.probe_runner is not None or bool(core_paths)
    if bundles and probe_runner_ready:
        runner_owned = options.probe_runner is None
        runner = options.probe_runner or SecurityProbeRunner(
            core_paths,
            endpoints=security_cfg["content"]["endpoints"],
            startup_timeout=float(security_cfg["probe"]["startup_timeout_seconds"]),
            timeout=float(security_cfg["content"]["timeout_seconds"]),
            max_body_bytes=int(security_cfg["content"]["max_body_bytes"]),
        )
        probe_concurrency = max(1, int(security_cfg["probe"]["concurrency"]))
        runnable = [
            bundle for bundle in bundles
            if bundle.config is not None
        ]
        with ThreadPoolExecutor(max_workers=probe_concurrency) as pool:
            futures = {}
            for bundle in runnable:
                preferred_core = str(bundle.entry.get("runtime_core") or "") or None
                if runner_owned:
                    future = pool.submit(
                        runner.probe_node, bundle.config, bundle.resolved_ip, preferred_core
                    )
                else:
                    # Existing injected test doubles use the historical two-arg signature.
                    future = pool.submit(runner.probe_node, bundle.config, bundle.resolved_ip)
                futures[future] = bundle.safe_id
            for future in as_completed(futures):
                safe_id = futures[future]
                try:
                    probes[safe_id] = future.result()
                except Exception:  # defensive: probing never kills the stage
                    probes[safe_id] = NodeProbeResult()
        if runner_owned:
            runner.cleanup()

    # -- 6. policy decisions ----------------------------------------------------
    # Metadata-only bundles (a live_nodes.json entry whose URI left the
    # filtered subscription on a previous run) are carried over verbatim:
    # they can never be republished, and re-evaluating them would break
    # byte-determinism of repeated runs.
    threshold = int(security_cfg["content"]["failure_threshold"])
    quarantine_on_incomplete = bool(security_cfg["policy"]["quarantine_on_incomplete"])
    # Cloudflare-zero invariant + ASN completeness (publish guarantee):
    # a node may only be published when its ASN is known AND is neither
    # a forbidden (Cloudflare) ASN nor an explicitly Cloudflare org.
    forbidden_asns = frozenset(
        int(asn) for asn in (security_cfg["policy"].get("forbidden_asns") or [])
    )
    require_asn = bool(security_cfg["policy"].get("require_asn_for_publish", True))
    decisions: dict[str, SecurityDecision] = {}
    reputation_hits: dict[str, list[str]] = {}
    for bundle in bundles:
        key = bundle.safe_id or "unparsed"
        if bundle.config is None and not bundle.parse_failed:
            previous = bundle.entry.get("security_status")
            if previous:
                # Preserve the original decision reasons (e.g. a node
                # blocked as cloudflare_network_forbidden in an earlier
                # run) so repeated runs keep identical statistics.
                carried_reasons = [
                    str(reason)
                    for reason in (bundle.entry.get("security_reasons") or [])
                ]
                decisions[key] = SecurityDecision(
                    status=str(previous),
                    risk_score=int(bundle.entry.get("security_risk_score", 80) or 0),
                    reasons=carried_reasons or ["carried_over_metadata"],
                    checks_complete=bool(bundle.entry.get("security_checks_complete", False)),
                )
            continue
        ip = evidence_ip.get(bundle.safe_id)
        asn_info = asn_map.get(ip or "") or AsnInfo()
        hits: list[str] = []
        if ip and ip_in_drop_networks(ip, feed_view.drop_networks):
            hits.append("spamhaus_drop")
        if (
            asn_info.asn is not None
            and asn_info.asn in feed_view.asndrop_asns
        ):
            hits.append("spamhaus_asndrop")
        if ip and ip in feed_view.feodo_ips:
            hits.append("feodo_active_c2")
        reputation_hits[key] = hits
        if bundle.parse_failed:
            decision = SecurityDecision(
                status=STATUS_QUARANTINE,
                risk_score=80,
                reasons=["security_reparse_failed"],
                checks_complete=False,
            )
            decisions[key] = decision
            continue
        cloudflare_network = (
            asn_info.asn is not None and asn_info.asn in forbidden_asns
        )
        cloudflare_org = (
            not cloudflare_network
            and is_cloudflare_org_name(asn_info.as_name)
        )
        dns_evidence = dns_map.get(bundle.safe_id)
        node_probe = probes.get(bundle.safe_id)
        decision = evaluate_node(
            _build_evidence(
                resolved_ip=ip,
                hits=hits,
                dns_evidence=dns_evidence,
                node_probe=node_probe,
                asn_info=asn_info,
                threshold=threshold,
                quarantine_on_incomplete=quarantine_on_incomplete,
                cloudflare_network_hit=cloudflare_network,
                cloudflare_org_hit=cloudflare_org,
                require_asn=require_asn,
            )
        )
        decisions[key] = decision

    # -- 7. ASN concentration cap on the publishable ranking --------------------
    cap = int(security_cfg["policy"]["max_nodes_per_asn"])
    publishable_bundles = [
        bundle for bundle in bundles
        if bundle.config is not None
        and decisions.get(bundle.safe_id)
        and decisions[bundle.safe_id].status in PUBLISHABLE_STATUSES
    ]
    ordered_publishable = _stable_order(publishable_bundles, node_entries)
    capped, excluded_by_cap = _apply_asn_cap(
        ordered_publishable, {b.safe_id: (asn_map.get(evidence_ip.get(b.safe_id) or "") or AsnInfo()).asn for b in publishable_bundles}, cap
    )
    pre_cap_ids = {bundle.safe_id for bundle in ordered_publishable}
    excluded_ids = {bundle.safe_id for bundle in excluded_by_cap}

    selected_bundles = [
        bundle for bundle in capped
        if bool(bundle.entry.get("selected")) and bundle.safe_id not in excluded_ids
    ]

    # -- 8. rewrite outputs ------------------------------------------------------
    publishable_total = len(capped)
    selected_total = len(selected_bundles)
    _rewrite_outputs(
        output_dir=output_dir,
        bundles=bundles,
        node_entries=node_entries,
        capped=capped,
        selected=selected_bundles,
        pre_cap_ids=pre_cap_ids,
        excluded_ids=excluded_ids,
        decisions=decisions,
        reputation_hits=reputation_hits,
        dns_map=dns_map,
        probes=probes,
        asn_map=asn_map,
        evidence_ip=evidence_ip,
        stats=stats,
        live_total=live_total,
        publishable_total=publishable_total,
        feed_statuses=feed_statuses,
        feed_age=result.feed_age_hours,
    )

    result.status = STAGE_STATUS_OK
    result.publishable_total = publishable_total
    result.selected_total = selected_total
    result.stats_updates = {
        "security_checked": len(bundles),
        "security_publishable": publishable_total,
        **{k: v for k, v in summarize_decisions(decisions).items()},
        "cloudflare_nodes_blocked": sum(
            1 for decision in decisions.values()
            if decision.status == STATUS_BLOCK
            and any(
                str(reason).startswith("cloudflare_")
                for reason in decision.reasons
            )
        ),
        "unique_asns": len({info.asn for info in asn_map.values() if info.asn}),
        "security_feed_status": _feed_status_label(feed_statuses),
        "security_feed_age": result.feed_age_hours,
    }
    return result


def _build_evidence(
    *,
    resolved_ip: str | None,
    hits: list[str],
    dns_evidence: DnsEvidence | None,
    node_probe: NodeProbeResult | None,
    asn_info: AsnInfo,
    threshold: int,
    quarantine_on_incomplete: bool,
    cloudflare_network_hit: bool = False,
    cloudflare_org_hit: bool = False,
    require_asn: bool = False,
):
    from .policy import NodeSecurityEvidence

    return NodeSecurityEvidence(
        resolved_ip=resolved_ip,
        spamhaus_drop_hit="spamhaus_drop" in hits,
        asndrop_hit="spamhaus_asndrop" in hits,
        feodo_hit="feodo_active_c2" in hits,
        cloudflare_network_hit=cloudflare_network_hit,
        cloudflare_org_hit=cloudflare_org_hit,
        require_asn=require_asn,
        dns=dns_evidence,
        probes=node_probe,
        asn=asn_info,
        content_failure_threshold=threshold,
        quarantine_on_incomplete=quarantine_on_incomplete,
    )


def _stable_order(bundles: list, node_entries: list[dict]) -> list:
    """Order publishable nodes by the pipeline's original ranking order."""
    order = {str(entry.get("safe_id")): index for index, entry in enumerate(node_entries)}
    return sorted(
        bundles,
        key=lambda bundle: (
            order.get(str(bundle.safe_id), 10**9),
            bundle.safe_id,
        ),
    )


def _apply_asn_cap(bundles: list, asn_by_safe_id: dict, cap: int) -> tuple[list, list]:
    """Keep at most ``cap`` nodes per announcing ASN (order preserved)."""
    if cap is None or int(cap) <= 0:
        return list(bundles), []
    cap = int(cap)
    counts: Counter = Counter()
    kept: list = []
    excluded: list = []
    for bundle in bundles:
        asn = asn_by_safe_id.get(bundle.safe_id)
        if asn is None:
            kept.append(bundle)  # unknown ASN: cannot be counted, keep
            continue
        if counts[asn] >= cap:
            excluded.append(bundle)
            continue
        counts[asn] += 1
        kept.append(bundle)
    return kept, excluded


def _feed_status_label(statuses: dict) -> str:
    """Aggregate feed statuses into the single stats label."""
    values = set(statuses.values())
    if not values or "downloaded" in values:
        return "fresh"
    if "cached" in values:
        return "cached"
    return "fresh"


def _load_testing_file(path: Path) -> dict:
    """Load the full testing config for security + verified-core discovery."""
    import yaml

    cfg_path = Path(path)
    if not cfg_path.is_file():
        return {}
    try:
        raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return raw if isinstance(raw, dict) else {}


# ---------------------------------------------------------------------------
# Output rewriting
# ---------------------------------------------------------------------------


def _rewrite_outputs(
    *,
    output_dir: Path,
    bundles: list,
    node_entries: list,
    capped: list,
    selected: list,
    pre_cap_ids: set,
    excluded_ids: set,
    decisions: dict,
    reputation_hits: dict,
    dns_map: dict,
    probes: dict,
    asn_map: dict,
    evidence_ip: dict,
    stats: dict,
    live_total: int,
    publishable_total: int,
    feed_statuses: dict,
    feed_age: float | None,
) -> None:
    """Rewrite live outputs in place (security-filtered, deterministic)."""
    output_dir = Path(output_dir)

    publishable_uris = [bundle.uri for bundle in capped if bundle.uri]
    body = "\n".join(publishable_uris) + ("\n" if publishable_uris else "")
    (output_dir / "live_subscription.txt").write_text(body, encoding="utf-8", newline="\n")
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    (output_dir / "live_subscription_base64.txt").write_text(encoded + "\n", encoding="ascii", newline="\n")

    best_uris = [bundle.uri for bundle in selected if bundle.uri]
    best_body = "\n".join(best_uris) + ("\n" if best_uris else "")
    (output_dir / "best.txt").write_text(best_body, encoding="utf-8", newline="\n")

    # countries/: exactly the security-filtered selected set.
    countries_dir = output_dir / "countries"
    countries_dir.mkdir(exist_ok=True)
    for old in countries_dir.glob("*.txt"):
        old.unlink()
    by_country: dict[str, list[str]] = {}
    for bundle in selected:
        if not bundle.uri:
            continue
        code = str(bundle.entry.get("country_code") or "UNKNOWN")
        by_country.setdefault(code, []).append(bundle.uri)
    for code, uris in sorted(by_country.items()):
        (countries_dir / f"{code}.txt").write_text(
            "\n".join(uris) + "\n", encoding="utf-8", newline="\n"
        )

    # live_nodes.json: every LIVE node stays listed, enriched with
    # security metadata; selection flags reflect the filtered set. The
    # original entry order is preserved so repeated runs stay byte-
    # identical (deterministic publish).
    selected_ids = {bundle.safe_id for bundle in selected}
    bundles_by_id = {bundle.safe_id: bundle for bundle in bundles if bundle.safe_id}
    enriched = []
    for original in node_entries:
        if not isinstance(original, dict) or not original.get("safe_id"):
            continue
        key = str(original["safe_id"])
        bundle = bundles_by_id.get(key)

        # Metadata-only entries (URI left the filtered subscription in an
        # earlier run) are carried over verbatim: they can never be
        # republished, and re-evaluating them would break determinism.
        if bundle is None or (bundle.config is None and not bundle.parse_failed):
            if "security_status" in original:
                enriched.append(dict(original))
                continue
            # First-run metadata without a URI should not exist; treat as
            # a metadata gap rather than silently publishing it.
            entry = dict(original)
            entry.update({
                "security_status": STATUS_QUARANTINE,
                "security_risk_score": 80,
                "security_reasons": ["metadata_without_uri"],
                "security_checks_complete": False,
                "reputation_hits": [],
                "dns_status": "not_applicable",
                "tls_status": "incomplete",
                "content_integrity_status": "incomplete",
                "selected": False,
                "asn_diversity_excluded": False,
            })
            enriched.append(entry)
            continue

        if bundle.parse_failed:
            decision = decisions.get(key) or SecurityDecision(
                status=STATUS_QUARANTINE, risk_score=80,
                reasons=["security_reparse_failed"], checks_complete=False,
            )
            entry = {
                "safe_id": key,
                "protocol": "unknown",
                "status": "live",
                "selected": False,
                "country_code": "UNKNOWN",
                "country_name": "Unknown",
                "resolved_ip": None,
                "tcp_latency_ms": None,
                "proxy_latency_ms": None,
                "success_ratio": 0.0,
                "score": 0,
                "asn": None, "as_name": None, "prefix": None,
                "reputation_hits": [],
                "dns_status": "not_applicable",
                "tls_status": "incomplete",
                "content_integrity_status": "incomplete",
                "security_status": decision.status,
                "security_risk_score": decision.risk_score,
                "security_reasons": list(decision.reasons),
                "security_checks_complete": False,
                "asn_diversity_excluded": False,
            }
            enriched.append(entry)
            continue

        decision = decisions.get(key)
        if decision is None:
            decision = SecurityDecision(
                status=STATUS_QUARANTINE, risk_score=80,
                reasons=["security_metadata_gap"], checks_complete=False,
            )
        entry = dict(original)
        # The security decision was evaluated against evidence_ip; the entry
        # must carry the ASN of that same endpoint. resolved_ip stays None
        # for hostname nodes (no runner-resolved pinning), so fall back to
        # the evidence IP for ASN metadata only.
        ip = (
            bundle.resolved_ip
            or entry.get("resolved_ip")
            or evidence_ip.get(key)
        )
        asn_info = asn_map.get(ip or "") or AsnInfo()
        dns_evidence = dns_map.get(key)
        probe = probes.get(key)
        entry["asn"] = asn_info.asn
        entry["as_name"] = asn_info.as_name
        entry["prefix"] = asn_info.prefix
        entry["reputation_hits"] = sorted(reputation_hits.get(key, []))
        entry["dns_status"] = _dns_label(dns_evidence)
        entry["tls_status"] = _tls_label(probe)
        entry["content_integrity_status"] = _content_label(probe)
        entry["security_status"] = decision.status
        entry["security_risk_score"] = decision.risk_score
        entry["security_reasons"] = list(decision.reasons)
        entry["security_checks_complete"] = decision.checks_complete
        entry["selected"] = key in selected_ids
        # Diversity-capped nodes pass policy but are not published.
        entry["asn_diversity_excluded"] = (
            key in excluded_ids and key in pre_cap_ids
        )
        enriched.append(entry)
    (output_dir / "live_nodes.json").write_text(
        json.dumps(enriched, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",newline="\n"
    )

    # stats: publishable counts + full security statistics block. The
    # security counters are derived from the *final* enriched entries so
    # that carried-over metadata keeps repeated runs byte-identical.
    count_by_country = dict(sorted(
        Counter(
            str(bundle.entry.get("country_code") or "UNKNOWN")
            for bundle in selected if bundle.uri
        ).items()
    ))
    count_by_protocol = dict(sorted(
        Counter(
            (bundle.config.protocol if bundle.config else "unknown")
            for bundle in selected if bundle.uri
        ).items()
    ))
    asn_counter = Counter(
        entry["asn"] for entry in enriched
        if isinstance(entry.get("asn"), int)
    )
    top_asns = [
        {"asn": asn, "count": count}
        for asn, count in sorted(asn_counter.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
    ]
    status_counts = Counter(
        str(entry.get("security_status")) for entry in enriched
    )
    stats_updates = {
        # recorded once (first security run); repeated runs keep the
        # original pre-security count for stable, deterministic output
        "pre_security_live_total": stats.get(
            "pre_security_live_total", stats.get("live_total", live_total)
        ),
        "live_total": publishable_total,
        "live_selected": len(selected),
        "count_by_country": count_by_country,
        "count_by_protocol_live": count_by_protocol,
        "security_checked": len(bundles),
        "security_publishable": publishable_total,
        "security_allowed": status_counts.get("allow", 0),
        "security_allowed_with_warnings": status_counts.get("allow_with_warnings", 0),
        "security_quarantined": status_counts.get("quarantine", 0),
        "security_blocked": status_counts.get("block", 0),
        # Cloudflare-zero invariant: how many nodes were hard-blocked
        # because their endpoint sits on a Cloudflare network (forbidden
        # ASN or explicit Cloudflare organisation identity).
        "cloudflare_nodes_blocked": sum(
            1 for e in enriched
            if e.get("security_status") == STATUS_BLOCK
            and any(
                str(reason).startswith("cloudflare_")
                for reason in (e.get("security_reasons") or [])
            )
        ),
        # ASN completeness guarantee: nodes quarantined solely because
        # their ASN could not be determined (never publishable).
        "asn_unknown_quarantined": sum(
            1 for e in enriched
            if e.get("security_status") == STATUS_QUARANTINE
            and "asn_unknown" in (e.get("security_reasons") or [])
        ),
        "spamhaus_drop_hits": sum(
            1 for e in enriched if "spamhaus_drop" in (e.get("reputation_hits") or [])
        ),
        "spamhaus_asndrop_hits": sum(
            1 for e in enriched if "spamhaus_asndrop" in (e.get("reputation_hits") or [])
        ),
        "feodo_hits": sum(
            1 for e in enriched if "feodo_active_c2" in (e.get("reputation_hits") or [])
        ),
        "dns_anomalies": sum(
            1 for e in enriched
            if e.get("dns_status") in ("rebinding_suspected", "bogon_answer")
        ),
        "tls_anomalies": sum(
            1 for e in enriched
            if str(e.get("tls_status", "")).startswith("validation_failed")
        ),
        "content_integrity_failures": sum(
            1 for e in enriched if e.get("content_integrity_status") == "failed"
        ),
        "unique_asns": len(asn_counter),
        "top_asns_by_count": top_asns,
        "security_feed_status": _feed_status_label(feed_statuses),
        "security_feed_age": feed_age,
    }
    stats.update(stats_updates)
    (output_dir / "live_stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",newline="\n"
    )

    _write_diagnostics(
        output_dir=output_dir,
        bundles=bundles,
        decisions=decisions,
        reputation_hits=reputation_hits,
        dns_map=dns_map,
        probes=probes,
        asn_map=asn_map,
        evidence_ip=evidence_ip,
        excluded_ids=excluded_ids,
        feed_statuses=feed_statuses,
        feed_age=feed_age,
    )


def _dns_label(dns_evidence: DnsEvidence | None) -> str:
    if dns_evidence is None:
        return "not_applicable"
    if dns_evidence.anomaly == "rebinding":
        return "rebinding_suspected"
    if dns_evidence.anomaly == "bogon_answer":
        return "bogon_answer"
    if dns_evidence.status == "unresolved":
        return "unresolved"
    if dns_evidence.benign_mismatch:
        return "public_mismatch"
    if dns_evidence.host_kind == "ip_literal":
        return "ip_literal"
    return "ok"


def _tls_label(probe: NodeProbeResult | None) -> str:
    if probe is None or not probe.endpoints:
        return "incomplete"
    if probe.tls_ok_count == 0 and probe.tls_cert_failures > 0:
        return "validation_failed:" + (
            ",".join(probe.cert_error_categories()) or "unknown"
        )
    if probe.tls_inconclusive == len(probe.endpoints):
        return "inconclusive"
    return "ok"


def _content_label(probe: NodeProbeResult | None) -> str:
    if probe is None or not probe.endpoints:
        return "incomplete"
    if probe.content_checked == 0:
        return "incomplete" if probe.endpoints else "not_checked"
    if probe.content_failures >= 2:
        return "failed"
    if probe.content_failures == 1:
        return "warning"
    return "ok"


def _write_diagnostics(
    *,
    output_dir: Path,
    bundles: list,
    decisions: dict,
    reputation_hits: dict,
    dns_map: dict,
    probes: dict,
    asn_map: dict,
    evidence_ip: dict,
    excluded_ids: set,
    feed_statuses: dict,
    feed_age: float | None,
) -> None:
    """Private per-node evidence (safe identifiers only, artifact-only)."""
    payload = {
        "generated_at": _iso_now(),
        "feed_statuses": feed_statuses,
        "feed_age_hours": feed_age,
        "note": "credential-free diagnostics; no URIs, UUIDs or passwords",
        "nodes": [],
    }
    for bundle in bundles:
        key = bundle.safe_id or "unparsed"
        decision = decisions.get(key)
        probe = probes.get(key)
        ip = evidence_ip.get(key)
        asn_info = asn_map.get(ip or "") or AsnInfo()
        dns_evidence = dns_map.get(key)
        payload["nodes"].append({
            "safe_id": key,
            "protocol": bundle.config.protocol if bundle.config else "unknown",
            "resolved_ip": ip,
            "reputation_hits": sorted(reputation_hits.get(key, [])),
            "dns": dns_evidence.to_dict() if dns_evidence else None,
            "tls_error_categories": probe.cert_error_categories() if probe else [],
            "content_failures": probe.content_failures if probe else 0,
            "certs": [c.to_dict() for c in probe.certs()] if probe else [],
            "asn": asn_info.to_dict(),
            "asn_diversity_excluded": key in excluded_ids,
            "decision": decision.to_dict() if decision else None,
        })
    (output_dir / "security_diagnostics.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",newline="\n"
    )


def _write_unavailable_diagnostics(output_dir: Path, reason: str, now) -> None:
    """Diagnostics artifact for a halted run (security feed outage)."""
    payload = {
        "generated_at": _iso_now(),
        "stage_status": STAGE_STATUS_UNAVAILABLE,
        "reason": reason,
        "note": "previous healthy public output preserved; nothing published",
    }
    (Path(output_dir) / "security_diagnostics.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",newline="\n"
    )


def _iso_now() -> str:
    return utc_now().isoformat(timespec="seconds")
