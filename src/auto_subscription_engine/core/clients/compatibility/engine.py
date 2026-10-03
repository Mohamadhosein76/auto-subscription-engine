"""Universal Client & Network Compatibility stage (multi-core orchestrator).

Pipeline position: AFTER the Security Deep Check, BEFORE the guarded
publish — exclusively on the small security-publishable LIVE set:

    LIVE/security-pass nodes
        -> per-core real runtime tests (sing-box / xray / hiddify / mihomo)
        -> per-core statuses + failure categories + latencies
        -> compatibility score (0..100, country-free)
        -> network resilience profiles
        -> diversity-aware client / network feeds
        -> UNIVERSAL feed = the common intersection of all cores
        -> rewrite of the live outputs + compatibility statistics

Main subscription policy (spec item 15): after this stage
``live_subscription.txt`` (published as ``public/subscription.txt``) IS
the universal feed — the conservative, multi-core-validated subset. The
previous URL keeps working; its content simply becomes trustworthy.

Core unavailability is safe by design: a core that could not be
installed/verified is reported ``unavailable``; the affected client feed
is NOT produced (the publisher keeps the previous good file) and the
universal feed is never built from unverified cores.
"""

from __future__ import annotations

import base64
import json
import logging
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ...scheduling import ReliabilityHistory
from ...discovery import SourceIntelligenceStore
from ...models import ParseError, ParsedConfig, UnknownProtocolError
from ...models.fingerprint import normalize_config
from ...protocols import parse_uri
from ...utils.redaction import redact_stderr
from ...utils.identity import config_safe_id
from ..builders.adapters import BUILDERS, node_support_summary
from .audit import node_features, unmapped_features
from .classify import (
    NetworkProfile,
    classify_network,
    mobile_safe_rank,
    network_feed_membership,
)
from .matrix import capabilities_for, universal_eligible
from .runner import CompatTestUrl, CoreTestResult, CoreTester
from ...scoring import compatibility_score, universal_rank_key, CompatScoreInput

logger = logging.getLogger(__name__)

STAGE_STATUS_OK = "ok"
STAGE_STATUS_DISABLED = "disabled"
STAGE_STATUS_UNAVAILABLE = "cores_unavailable"

#: Statuses a core can report for one node.
STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_UNSUPPORTED = "unsupported"
STATUS_UNAVAILABLE = "unavailable"
STATUS_UNTESTED = "untested"

DEFAULT_COMPAT_CONFIG: dict = {
    "enabled": True,
    "cores": ["singbox", "xray", "hiddify", "mihomo"],
    "startup_timeout_seconds": 8.0,
    "http_timeout_seconds": 8.0,
    "concurrency_per_core": 8,
    "soft_deadline_seconds_per_core": 420.0,
    "min_universal_nodes": 1,
    "min_feed_nodes": 3,
    "max_mobile_safe_nodes": 50,
    "test_urls": [
        {"url": "https://www.gstatic.com/generate_204", "expect_status": [200, 204]},
        {
            "url": "https://www.msftconnecttest.com/connecttest.txt",
            "expect_status": [200],
            "expect_substring": "Microsoft",
        },
    ],
    "diversity": {
        "per_asn_limit": 8,
        "per_prefix_limit": 4,
        "per_host_limit": 3,
        "per_source_soft_limit": 0.50,
    },
    "mobile_safe": {
        "max_latency_ms": 1500.0,
        "udp_share_cap": 0.2,
    },
}

#: Feeds produced by this stage: (kind, name). Kind "client" feeds are
#: keyed by core pass status; "network" feeds by network profile.
CLIENT_FEEDS = ("v2rayng", "hiddify", "nekobox", "singbox", "mihomo", "universal")
NETWORK_FEEDS = ("tcp", "udp", "ipv4", "ipv6", "port443", "mobile-safe")

FEED_SUFFIX_TXT = ".txt"
FEED_SUFFIX_B64 = "_base64.txt"

#: The universal feed replaces the main subscription content.
_CLIENT_FEED_TO_CORE = {"v2rayng": "xray", "hiddify": "hiddify", "nekobox": "singbox"}


@dataclass
class CompatOptions:
    """Inputs for one compatibility stage run."""

    output_dir: Path
    testing_config_path: Path
    #: core key -> installed (checksum-verified) binary path.
    core_paths: dict[str, Path] = field(default_factory=dict)
    history_path: Path | None = None
    discovery_state_path: Path | None = Path("data/discovery.json")
    #: Offline test hook: callable(core, binary_path, compat_cfg, test_urls) -> tester
    tester_factory: object | None = None
    core_versions: dict[str, str] | None = None


@dataclass
class CompatStageResult:
    """Credential-free outcome of one compatibility stage run."""

    status: str = STAGE_STATUS_OK
    reason: str | None = None
    checked_total: int = 0
    universal_total: int = 0
    feed_counts: dict = field(default_factory=dict)
    core_statuses: dict = field(default_factory=dict)
    stats_updates: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_compat_stage(options: CompatOptions) -> CompatStageResult:
    compat_cfg = _merged_compat_config(options.testing_config_path)
    result = CompatStageResult()
    if not compat_cfg.get("enabled", True):
        result.status = STAGE_STATUS_DISABLED
        result.reason = "compatibility layer disabled by configuration"
        return result

    output_dir = Path(options.output_dir)
    uris, node_entries, stats = _load_live_outputs(output_dir)
    bundles = _join_nodes(uris, node_entries)
    result.checked_total = len(bundles)

    cores = [str(c) for c in compat_cfg.get("cores", ["singbox", "xray", "hiddify", "mihomo"])]
    available: dict[str, bool] = {
        core: Path(options.core_paths.get(core, "")).is_file() for core in cores
    }
    result.core_statuses = {core: ("available" if ok else "unavailable") for core, ok in available.items()}

    core_versions = dict(options.core_versions or {})
    for core in cores:
        if available.get(core) and core not in core_versions:
            core_versions[core] = detect_core_version(core, Path(options.core_paths[core]))

    # -- per-node pre-evaluation (no runtime tests yet) -------------------------
    evaluations: dict[str, dict] = {}
    pending: dict[str, list[_Bundle]] = {core: [] for core in cores}
    per_core_reasons: dict[str, Counter] = {core: Counter() for core in cores}

    for bundle in bundles:
        key = bundle.safe_id
        if bundle.config is None:
            evaluations[key] = {
                "config": None, "features": None, "profile": None,
                "statuses": {}, "universal": False, "score": 0,
                "unsupported_features": [], "bundle": bundle,
            }
            continue
        config = bundle.config
        summary = node_support_summary(config)
        caps = summary["capabilities"]
        profile: NetworkProfile = summary["profile"]
        features = summary["features"]
        statuses: dict[str, dict] = {}

        for core in cores:
            capability = caps.get(core)
            if capability is not None and not capability.supported:
                statuses[core] = {
                    "status": STATUS_UNSUPPORTED,
                    "latency_ms": None,
                    "failure_category": capability.detail,
                }
                per_core_reasons[core][capability.detail.split(":")[0]] += 1
                continue
            if not available.get(core, False):
                statuses[core] = {
                    "status": STATUS_UNAVAILABLE, "latency_ms": None,
                    "failure_category": "core_unavailable",
                }
                continue
            statuses[core] = {
                "status": STATUS_UNTESTED, "latency_ms": None,
                "failure_category": None,
            }
            pending[core].append(bundle)

        evaluations[key] = {
            "config": config,
            "features": features,
            "profile": profile,
            "statuses": statuses,
            "universal": False,
            "score": 0,
            "unsupported_features": summary["unsupported_features"],
            "bundle": bundle,
        }

    # -- per-core runtime tests (bounded concurrency + soft deadline) ------------
    for core in cores:
        if not pending[core] or not available.get(core, False):
            continue
        tester = _make_tester(
            core, Path(options.core_paths[core]), compat_cfg, options, core_versions.get(core)
        )
        _run_core_tests(
            core, tester, pending[core], evaluations, per_core_reasons,
            concurrency=int(compat_cfg.get("concurrency_per_core", 8)),
            soft_deadline=float(compat_cfg.get("soft_deadline_seconds_per_core", 420.0)),
        )

    # -- finalize per-node universal/score ---------------------------------------
    for key, evaluation in evaluations.items():
        if evaluation["config"] is None:
            continue
        summary_eligible = universal_eligible(evaluation["features"])
        evaluation["universal"] = _is_universal(evaluation["statuses"], summary_eligible, cores)
        evaluation["score"] = _node_score(
            evaluation["config"], evaluation["profile"], evaluation["statuses"],
            evaluation["features"], cores,
        )

    # -- history: per-core records; source intelligence is separate ------------
    history = _record_history(options, bundles, evaluations, cores)
    discovery_state = _record_discovery_compat(options, bundles, evaluations)

    # -- feeds -------------------------------------------------------------------
    publishable_ids = [bundle.safe_id for bundle in bundles if bundle.config is not None]
    limits = compat_cfg.get("diversity", {})
    meta = _diversity_meta(evaluations)

    universal_ids = [
        key for key in publishable_ids if evaluations[key]["universal"]
    ]
    universal_ids = _rank_keys(universal_ids, evaluations, key_fn=_universal_order_key)
    universal_ids = apply_feed_diversity(
        universal_ids, meta,
        per_asn=int(limits.get("per_asn_limit", 8)),
        per_prefix=int(limits.get("per_prefix_limit", 4)),
        per_host=int(limits.get("per_host_limit", 3)),
        per_source_soft=float(limits.get("per_source_soft_limit", 0.5)),
        # The diversity floor is min_feed_nodes for EVERY feed, including
        # the universal one: the soft source-share limit may only trim a
        # group while >= min_feed_nodes nodes from OTHER sources are kept.
        # min_universal_nodes is the PUBLISH guard (below it the whole
        # publish is skipped), not a license to hollow the main
        # subscription down to that size (real-run lesson: a 33-node
        # all-core-validated pool with a single alternative-source node
        # collapsed 33 -> 2 under min_keep=1).
        min_keep=int(compat_cfg.get("min_feed_nodes", 3)),
    )

    feed_counts: dict[str, int] = {}
    core_unavailable_any = any(not ok for ok in available.values())

    # universal feed + main subscription replacement
    universal_uris = [evaluations[key]["bundle"].uri for key in universal_ids if evaluations[key]["bundle"].uri]
    if core_unavailable_any:
        # Never publish a "universal" feed built from unverified cores.
        universal_uris = []
    feed_counts["universal"] = len(universal_uris)

    # client feeds (xray/hiddify/nekobox)
    for feed, core in _CLIENT_FEED_TO_CORE.items():
        ids = [
            key for key in publishable_ids
            if evaluations[key]["statuses"].get(core, {}).get("status") == STATUS_PASS
        ]
        ids = _rank_keys(ids, evaluations, key_fn=_universal_order_key)
        ids = apply_feed_diversity(
            ids, meta,
            per_asn=int(limits.get("per_asn_limit", 8)),
            per_prefix=int(limits.get("per_prefix_limit", 4)),
            per_host=int(limits.get("per_host_limit", 3)),
            per_source_soft=float(limits.get("per_source_soft_limit", 0.5)),
            min_keep=int(compat_cfg.get("min_feed_nodes", 3)),
        )
        uris_feed = [evaluations[key]["bundle"].uri for key in ids if evaluations[key]["bundle"].uri]
        if not available.get(core, True) and core != "singbox":
            # A core that could not be verified produces NO feed this run;
            # the publisher preserves the previous good file instead.
            uris_feed = []
        feed_counts[feed] = len(uris_feed)

    # mihomo YAML feed
    mihomo_ids = [
        key for key in publishable_ids
        if evaluations[key]["statuses"].get("mihomo", {}).get("status") == STATUS_PASS
    ]
    mihomo_ids = _rank_keys(mihomo_ids, evaluations, key_fn=_universal_order_key)
    mihomo_ids = apply_feed_diversity(
        mihomo_ids, meta,
        per_asn=int(limits.get("per_asn_limit", 8)),
        per_prefix=int(limits.get("per_prefix_limit", 4)),
        per_host=int(limits.get("per_host_limit", 3)),
        per_source_soft=float(limits.get("per_source_soft_limit", 0.5)),
        min_keep=int(compat_cfg.get("min_feed_nodes", 3)),
    )
    if not available.get("mihomo", False):
        mihomo_ids = []
    feed_counts["mihomo"] = len(mihomo_ids)

    # Native sing-box JSON feed (same runtime truth as NekoBox, native schema).
    singbox_ids = [
        key for key in publishable_ids
        if evaluations[key]["statuses"].get("singbox", {}).get("status") == STATUS_PASS
    ]
    singbox_ids = _rank_keys(singbox_ids, evaluations, key_fn=_universal_order_key)
    singbox_ids = apply_feed_diversity(
        singbox_ids, meta,
        per_asn=int(limits.get("per_asn_limit", 8)),
        per_prefix=int(limits.get("per_prefix_limit", 4)),
        per_host=int(limits.get("per_host_limit", 3)),
        per_source_soft=float(limits.get("per_source_soft_limit", 0.5)),
        min_keep=int(compat_cfg.get("min_feed_nodes", 3)),
    )
    if not available.get("singbox", False):
        singbox_ids = []
    feed_counts["singbox"] = len(singbox_ids)

    # Network eligibility counts. Stage 10 owns the actual user-facing feeds.
    mobile_cfg = compat_cfg.get("mobile_safe", {})
    ordered_publishable = _rank_keys(publishable_ids, evaluations, key_fn=_universal_order_key)
    mobile_ids = _mobile_safe_ids(
        evaluations,
        ordered_publishable,
        cores,
        float(mobile_cfg.get("max_latency_ms", 1500.0)),
        int(compat_cfg.get("max_mobile_safe_nodes", 50)),
        float(mobile_cfg.get("udp_share_cap", 0.2)),
    )
    feed_counts["mobile-safe"] = len(mobile_ids)
    for feed in ("tcp", "udp", "ipv4", "ipv6", "port443"):
        ids = [
            key for key in ordered_publishable
            if _feed_member(evaluations[key], feed)
        ]
        feed_counts[feed] = len(ids)

    # -- rewrite live outputs ------------------------------------------------------
    universal_count = len(universal_uris)
    _rewrite_live_outputs(
        output_dir=output_dir,
        node_entries=node_entries,
        evaluations=evaluations,
        universal_uris=universal_uris,
        stats=stats,
        compat_cfg=compat_cfg,
        core_versions=core_versions,
        available=available,
        per_core_reasons=per_core_reasons,
        feed_counts=feed_counts,
        universal_count=universal_count,
        history=history,
        discovery_state=discovery_state,
    )

    _write_diagnostics(output_dir, evaluations, available, core_versions, feed_counts)

    result.status = STAGE_STATUS_OK
    result.universal_total = universal_count
    result.feed_counts = feed_counts
    result.stats_updates = {}
    return result


def _run_core_tests(
    core: str,
    tester: object,
    bundles: list[_Bundle],
    evaluations: dict,
    per_core_reasons: dict,
    *,
    concurrency: int,
    soft_deadline: float,
) -> None:
    """Run one core's pending node tests with bounded concurrency.

    Nodes that never start before the soft deadline keep the ``untested``
    status — they are excluded from the feeds but are never counted as
    network failures (the same policy as the live pipeline stage C).
    """
    deadline = time.monotonic() + soft_deadline

    def _worker(bundle: _Bundle):
        if time.monotonic() >= deadline:
            return None
        return tester.test_node(bundle.config, bundle.resolved_ip)

    try:
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
            futures = {pool.submit(_worker, bundle): bundle for bundle in bundles}
            for future in as_completed(futures):
                bundle = futures[future]
                try:
                    test = future.result()
                except Exception:  # defensive: a crashed test never kills the stage
                    test = CoreTestResult(core=core, status=STATUS_FAIL,
                                          failure_category="internal_error")
                if test is None:
                    continue  # not tested (deadline): stays "untested"
                statuses = evaluations[bundle.safe_id]["statuses"]
                statuses[core] = {
                    "status": test.status,
                    "latency_ms": test.latency_ms,
                    "failure_category": test.failure_category,
                }
                if test.status == STATUS_FAIL and test.failure_category:
                    per_core_reasons[core][test.failure_category.split(":")[0]] += 1
    finally:
        cleanup = getattr(tester, "cleanup", None)
        if callable(cleanup):
            cleanup()


# ---------------------------------------------------------------------------
# Helpers: loading / joining / per-node evaluation
# ---------------------------------------------------------------------------


def _load_live_outputs(output_dir: Path) -> tuple[list[str], list[dict], dict]:
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
class _Bundle:
    uri: str
    config: ParsedConfig | None
    safe_id: str
    entry: dict
    resolved_ip: str | None


def _join_nodes(uris: list[str], node_entries: list[dict]) -> list[_Bundle]:
    entries_by_id = {
        str(entry.get("safe_id")): entry
        for entry in node_entries
        if isinstance(entry, dict) and entry.get("safe_id")
    }
    bundles: list[_Bundle] = []
    seen: set[str] = set()
    for uri in uris:
        try:
            config = normalize_config(parse_uri(uri))
        except (ParseError, UnknownProtocolError, ValueError):
            config = None
        if config is None:
            bundles.append(_Bundle(uri=uri, config=None, safe_id=f"unparsed:{len(bundles)}", entry={}, resolved_ip=None))
            continue
        safe_id = config_safe_id(config)
        seen.add(safe_id)
        entry = entries_by_id.get(safe_id, {})
        bundles.append(_Bundle(
            uri=uri, config=config, safe_id=safe_id, entry=entry,
            resolved_ip=entry.get("resolved_ip"),
        ))
    return bundles


def _is_universal(statuses: dict, eligible: bool, cores: list[str]) -> bool:
    if not eligible:
        return False
    if statuses.get("singbox", {}).get("status") != STATUS_PASS:
        return False
    for core in cores:
        if statuses.get(core, {}).get("status") != STATUS_PASS:
            return False
    return True


def _node_score(
    config: ParsedConfig,
    profile: NetworkProfile,
    statuses: dict,
    features,
    cores: list[str],
) -> int:
    applicable = frozenset(
        core for core in ["singbox", *cores]
        if statuses.get(core, {}).get("status") in (STATUS_PASS, STATUS_FAIL)
    )
    passed = frozenset(
        core for core in ["singbox", *cores]
        if statuses.get(core, {}).get("status") == STATUS_PASS
    )
    latencies = {
        core: statuses.get(core, {}).get("latency_ms") for core in ["singbox", *cores]
    }
    return compatibility_score(CompatScoreInput(
        features=features,
        cores_passed=passed,
        cores_applicable=applicable,
        latencies_ms=latencies,
        tcp_based=profile.tcp,
        tls_or_reality=profile.tls or profile.reality,
        port_443=profile.port_443,
        ipv4=profile.ipv4,
    ))


# ---------------------------------------------------------------------------
# Feeds: ranking, diversity, mobile-safe
# ---------------------------------------------------------------------------


def _universal_order_key(key: str, evaluations: dict) -> tuple:
    evaluation = evaluations[key]
    latencies = {
        core: status.get("latency_ms")
        for core, status in evaluation["statuses"].items()
        if status.get("status") == STATUS_PASS
    }
    return universal_rank_key(
        compat_score=int(evaluation["score"]),
        latencies_ms=latencies,
        fingerprint=key,
    )


def _rank_keys(keys: list[str], evaluations: dict, *, key_fn) -> list[str]:
    return sorted(keys, key=lambda key: key_fn(key, evaluations))


def _diversity_meta(evaluations: dict) -> dict[str, dict]:
    meta: dict[str, dict] = {}
    for key, evaluation in evaluations.items():
        bundle: _Bundle = evaluation["bundle"]
        entry = bundle.entry or {}
        config = bundle.config
        profile = evaluation.get("profile")
        host_key = bundle.resolved_ip or (config.host if config else "") or ""
        meta[key] = {
            "asn": entry.get("asn"),
            "prefix": entry.get("prefix"),
            "host": host_key,
            "source": entry.get("source") or (config.source if config else "") or "unknown",
        }
    return meta


def apply_feed_diversity(
    ordered: list[str],
    meta: dict[str, dict],
    *,
    per_asn: int,
    per_prefix: int,
    per_host: int,
    per_source_soft: float,
    min_keep: int,
) -> list[str]:
    """Greedy selection + final-state soft-limit enforcement.

    Semantics (hardened by the compatibility-stage tests):

    - ``per_asn`` is a HARD cap: no more than ``per_asn`` nodes from one
      ASN are ever kept (same-datacenter dominance is the main real-feed
      skew risk, and an ASN cap that could not fire would make the
      per-ASN promise meaningless).
    - ``per_prefix`` / ``per_host`` / ``per_source_soft`` are SOFT,
      dominance-only limits: they trim a group ONLY while the feed still
      keeps at least ``max(min_keep, 1)`` nodes from *other* groups.
      A small pool that shares one prefix/host/source is never hollowed
      out — diversity must not shrink a feed without a real alternative.
    - Enforcement is final-state aware: trimming runs AFTER the greedy
      pass and drops the lowest-ranked over-limit nodes, so alternatives
      that arrive late in the ordering still shrink earlier over-limit
      groups (a purely greedy deferral cannot do that).
    """
    floor = max(int(min_keep), 1)
    kept: list[str] = []
    asn_counts: Counter = Counter()
    for key in ordered:
        item = meta[key]
        if per_asn > 0 and item["asn"] is not None and asn_counts[item["asn"]] >= per_asn:
            continue
        if item["asn"] is not None:
            asn_counts[item["asn"]] += 1
        kept.append(key)
    return _trim_soft_limits(
        kept, meta,
        per_prefix=per_prefix, per_host=per_host,
        per_source_soft=per_source_soft, floor=floor,
    )


def _trim_soft_limits(
    kept: list[str],
    meta: dict[str, dict],
    *,
    per_prefix: int,
    per_host: int,
    per_source_soft: float,
    floor: int,
) -> list[str]:
    """Final-state enforcement of the soft prefix/host/source limits.

    Each iteration recomputes group sizes over the CURRENT kept list,
    finds the lowest-ranked node of the first violating group and drops
    it. A group violates its limit when it is over the limit (or over
    the source share) AND nodes from other groups already cover the
    ``floor`` — otherwise the feed would be hollowed out. Dropping only
    ever shrinks the list, so the loop always terminates.
    """
    if not kept:
        return kept
    kept = list(kept)
    while True:
        total = len(kept)
        counts = {"prefix": Counter(), "host": Counter(), "source": Counter()}
        for key in kept:
            item = meta[key]
            if item["prefix"]:
                counts["prefix"][item["prefix"]] += 1
            if item["host"]:
                counts["host"][item["host"]] += 1
            counts["source"][item["source"]] += 1

        drop_key: str | None = None
        for kind, limit, share in (
            ("prefix", per_prefix, None),
            ("host", per_host, None),
            ("source", None, per_source_soft),
        ):
            if kind == "source":
                if share is None or share <= 0:
                    continue
                for idx in range(total - 1, -1, -1):
                    item = meta[kept[idx]]
                    group = item["source"]
                    over = counts["source"][group] > max(share * total, 1.0)
                    if over and (total - counts["source"][group]) >= floor:
                        drop_key = kept[idx]
                        break
            else:
                if limit is None or limit <= 0:
                    continue
                for idx in range(total - 1, -1, -1):
                    item = meta[kept[idx]]
                    group = item[kind]
                    if not group:
                        continue
                    over = counts[kind][group] > limit
                    if over and (total - counts[kind][group]) >= floor:
                        drop_key = kept[idx]
                        break
            if drop_key is not None:
                break

        if drop_key is None:
            return kept
        kept.remove(drop_key)


def _feed_member(evaluation: dict, feed: str) -> bool:
    profile: NetworkProfile | None = evaluation.get("profile")
    if profile is None:
        return False
    return network_feed_membership(profile).get(feed, False)


def _mobile_safe_ids(
    evaluations: dict,
    ordered: list[str],
    cores: list[str],
    max_latency_ms: float,
    max_nodes: int,
    udp_share_cap: float,
) -> list[str]:
    """Conservative mobile/restricted-network candidates (spec item 17)."""
    eligible: list[tuple[tuple, str]] = []
    for key in ordered:
        evaluation = evaluations[key]
        profile: NetworkProfile | None = evaluation.get("profile")
        config = evaluation["config"]
        if profile is None or config is None or not profile.ipv4:
            continue
        statuses = evaluation["statuses"]
        singbox_ok = statuses.get("singbox", {}).get("status") == STATUS_PASS
        hiddify_ok = statuses.get("hiddify", {}).get("status") in (STATUS_PASS, STATUS_UNSUPPORTED)
        xray_ok = statuses.get("xray", {}).get("status") in (STATUS_PASS, STATUS_UNSUPPORTED)
        if not (singbox_ok and hiddify_ok and xray_ok):
            continue
        latencies = {
            core: status.get("latency_ms")
            for core, status in statuses.items()
            if status.get("status") == STATUS_PASS
        }
        latencies["singbox"] = statuses.get("singbox", {}).get("latency_ms")
        worst = max([v for v in latencies.values() if v is not None], default=None)
        if worst is not None and worst > max_latency_ms:
            continue
        entry = evaluation["bundle"].entry or {}
        scored_cores = tuple(dict.fromkeys(cores))
        rank = mobile_safe_rank(
            profile,
            protocol=config.protocol,
            cores_passed_fraction=(
                sum(1 for core in scored_cores if statuses.get(core, {}).get("status") == STATUS_PASS)
                / max(1, len(scored_cores))
            ),
            proxy_latency_ms=worst,
            rolling_success_rate=entry.get("history_rolling_success_rate"),
            max_latency_ms=max_latency_ms,
        )
        eligible.append((rank, key))
    eligible.sort()
    selected = [key for _rank, key in eligible[:max_nodes]]
    return _apply_udp_share_cap(selected, evaluations, udp_share_cap)


def _apply_udp_share_cap(selected: list[str], evaluations: dict, share_cap: float) -> list[str]:
    """UDP-only nodes never dominate the mobile feed (TCP alternatives first)."""
    if not selected:
        return selected
    tcp_total = sum(1 for key in selected if evaluations[key]["profile"].tcp)
    udp_limit = int(share_cap * (tcp_total / (1 - share_cap))) if share_cap < 1 and tcp_total else len(selected)
    kept: list[str] = []
    udp_count = 0
    for key in selected:
        profile = evaluations[key]["profile"]
        if not profile.tcp:
            if udp_count >= max(udp_limit, 0) and tcp_total:
                continue
            udp_count += 1
        kept.append(key)
    return kept


# ---------------------------------------------------------------------------
# Output rewriting / stats / diagnostics
# ---------------------------------------------------------------------------


def _rewrite_live_outputs(
    *,
    output_dir: Path,
    node_entries: list[dict],
    evaluations: dict,
    universal_uris: list[str],
    stats: dict,
    compat_cfg: dict,
    core_versions: dict,
    available: dict,
    per_core_reasons: dict,
    feed_counts: dict,
    universal_count: int,
    history: ReliabilityHistory,
    discovery_state: SourceIntelligenceStore,
) -> None:
    enriched: list[dict] = []
    for original in node_entries:
        if not isinstance(original, dict) or not original.get("safe_id"):
            continue
        key = str(original["safe_id"])
        evaluation = evaluations.get(key)
        entry = dict(original)
        if evaluation is None or evaluation["config"] is None:
            entry.update({
                "singbox_compatible": entry.get("singbox_compatible", None),
                "xray_compatible": None,
                "hiddify_compatible": None,
                "mihomo_compatible": None,
                "universal_compatible": False,
                "compatibility_score": 0,
                "network_profile": {},
            })
            enriched.append(entry)
            continue

        statuses = evaluation["statuses"]
        entry["singbox_compatible"] = statuses.get("singbox", {}).get("status")
        entry["xray_compatible"] = statuses.get("xray", {}).get("status")
        entry["hiddify_compatible"] = statuses.get("hiddify", {}).get("status")
        entry["mihomo_compatible"] = statuses.get("mihomo", {}).get("status")
        entry["universal_compatible"] = bool(evaluation["universal"])
        entry["compatibility_score"] = int(evaluation["score"])
        profile: NetworkProfile = evaluation["profile"]
        entry["network_profile"] = profile.to_dict()
        compat_latency = {
            core: status.get("latency_ms")
            for core, status in statuses.items()
            if status.get("latency_ms") is not None
        }
        if compat_latency:
            entry["compat_latency_ms"] = compat_latency
        failures = {
            core: status.get("failure_category")
            for core, status in statuses.items()
            if status.get("failure_category")
        }
        if failures:
            entry["compat_failure_categories"] = failures
        if evaluation["unsupported_features"]:
            entry["parser_feature_unsupported"] = evaluation["unsupported_features"]
        enriched.append(entry)

    (output_dir / "live_nodes.json").write_text(
        json.dumps(enriched, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    # -- compatibility statistics ------------------------------------------------
    cores = [str(c) for c in compat_cfg.get("cores", ["singbox", "xray", "hiddify", "mihomo"])]
    per_protocol: dict[str, dict] = {}
    for entry in enriched:
        protocol = str(entry.get("protocol") or "unknown")
        bucket = per_protocol.setdefault(protocol, {
            "total": 0, "universal": 0, "xray_pass": 0, "hiddify_pass": 0, "mihomo_pass": 0,
        })
        bucket["total"] += 1
        bucket["universal"] += 1 if entry.get("universal_compatible") else 0
        bucket["xray_pass"] += 1 if entry.get("xray_compatible") == STATUS_PASS else 0
        bucket["hiddify_pass"] += 1 if entry.get("hiddify_compatible") == STATUS_PASS else 0
        bucket["mihomo_pass"] += 1 if entry.get("mihomo_compatible") == STATUS_PASS else 0

    latency_by_core: dict[str, list[float]] = {core: [] for core in cores}
    for entry in enriched:
        for core, value in (entry.get("compat_latency_ms") or {}).items():
            if isinstance(value, (int, float)):
                latency_by_core.setdefault(core, []).append(float(value))

    source_quality = discovery_state.summary()

    compat_stats = {
        "enabled": True,
        "core_versions": {core: version for core, version in core_versions.items()},
        "cores_available": {core: bool(available.get(core)) for core in available},
        "singbox_pass": sum(1 for e in enriched if e.get("singbox_compatible") == STATUS_PASS),
        "xray_tested": sum(1 for e in enriched if e.get("xray_compatible") in (STATUS_PASS, STATUS_FAIL)),
        "xray_pass": sum(1 for e in enriched if e.get("xray_compatible") == STATUS_PASS),
        "hiddify_tested": sum(1 for e in enriched if e.get("hiddify_compatible") in (STATUS_PASS, STATUS_FAIL)),
        "hiddify_pass": sum(1 for e in enriched if e.get("hiddify_compatible") == STATUS_PASS),
        "mihomo_tested": sum(1 for e in enriched if e.get("mihomo_compatible") in (STATUS_PASS, STATUS_FAIL)),
        "mihomo_pass": sum(1 for e in enriched if e.get("mihomo_compatible") == STATUS_PASS),
        "universal_pass": universal_count,
        "mobile_safe_count": feed_counts.get("mobile-safe", 0),
        "feed_counts": dict(feed_counts),
        "per_protocol_compatibility": dict(sorted(per_protocol.items())),
        "failure_reasons": {
            core: dict(sorted(reasons.items())) for core, reasons in sorted(per_core_reasons.items())
        },
        "median_latency_ms": {
            core: _median(values) for core, values in sorted(latency_by_core.items())
        },
        "source_quality": source_quality,
    }
    stats.update({
        "universal_count": universal_count,
        "compatibility": compat_stats,
        **{
            key: compat_stats[key]
            for key in (
                "singbox_pass", "xray_tested", "xray_pass", "hiddify_tested",
                "hiddify_pass", "mihomo_tested", "mihomo_pass", "mobile_safe_count",
            )
        },
    })
    (output_dir / "live_stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _write_diagnostics(
    output_dir: Path,
    evaluations: dict,
    available: dict,
    core_versions: dict,
    feed_counts: dict,
) -> None:
    nodes = []
    for key, evaluation in sorted(evaluations.items()):
        nodes.append({
            "safe_id": key,
            "protocol": evaluation["config"].protocol if evaluation["config"] else "unknown",
            "statuses": {
                core: {
                    "status": status.get("status"),
                    "failure_category": status.get("failure_category"),
                    "latency_ms": status.get("latency_ms"),
                }
                for core, status in evaluation["statuses"].items()
            },
            "universal_compatible": bool(evaluation["universal"]),
            "compatibility_score": int(evaluation["score"]),
            "parser_feature_unsupported": evaluation["unsupported_features"],
        })
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        "cores_available": {core: bool(ok) for core, ok in available.items()},
        "core_versions": dict(core_versions),
        "feed_counts": dict(feed_counts),
        "note": "credential-free diagnostics; no URIs, UUIDs or passwords",
        "nodes": nodes,
    }
    (Path(output_dir) / "compat_diagnostics.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# History (per-core + source quality)
# ---------------------------------------------------------------------------


def _record_history(
    options: CompatOptions,
    bundles: list[_Bundle],
    evaluations: dict,
    cores: list[str],
) -> ReliabilityHistory:
    history = ReliabilityHistory.load(options.history_path)
    for bundle in bundles:
        evaluation = evaluations.get(bundle.safe_id)
        if evaluation is None or evaluation["config"] is None:
            continue
        for core, status in evaluation["statuses"].items():
            if status["status"] in (STATUS_PASS, STATUS_FAIL):
                history.record_core(
                    bundle.config.fingerprint,
                    core,
                    passed=status["status"] == STATUS_PASS,
                )
    if options.history_path is not None:
        try:
            history.save(options.history_path)
        except OSError as exc:
            logger.warning("cannot persist history: %s", exc)
    return history


def _record_discovery_compat(
    options: CompatOptions,
    bundles: list[_Bundle],
    evaluations: dict,
) -> SourceIntelligenceStore:
    """Feed per-source compatibility outcomes into discovery intelligence."""
    store = SourceIntelligenceStore.load(options.discovery_state_path)
    by_source: dict[str, dict[str, int]] = {}
    for bundle in bundles:
        if bundle.config is None:
            continue
        evaluation = evaluations.get(bundle.safe_id)
        if evaluation is None:
            continue
        source = str((bundle.entry or {}).get("source") or bundle.config.source or "")
        if not source:
            continue
        bucket = by_source.setdefault(source, {"tested": 0, "passed": 0})
        statuses = evaluation.get("statuses") or {}
        considered = [
            status for status in statuses.values()
            if status.get("status") in (STATUS_PASS, STATUS_FAIL)
        ]
        if considered:
            bucket["tested"] += 1
            if any(status.get("status") == STATUS_PASS for status in considered):
                bucket["passed"] += 1
    for source, bucket in sorted(by_source.items()):
        store.record_verification_by_name(
            source,
            compat_tested=bucket["tested"],
            compat_passed=bucket["passed"],
        )
    try:
        store.save(options.discovery_state_path)
    except OSError as exc:
        logger.warning("cannot persist discovery source intelligence: %s", exc)
    return store


# ---------------------------------------------------------------------------
# Config / testers / versions
# ---------------------------------------------------------------------------


def _merged_compat_config(testing_config_path: Path) -> dict:
    merged = json.loads(json.dumps(DEFAULT_COMPAT_CONFIG))
    path = Path(testing_config_path)
    if path.is_file():
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            raw = {}
        compat = raw.get("compatibility") if isinstance(raw, dict) else None
        if isinstance(compat, dict):
            for section, values in compat.items():
                if isinstance(values, dict) and isinstance(merged.get(section), dict):
                    merged[section].update(values)
                else:
                    merged[section] = values
    return merged


def _make_tester(
    core: str,
    binary_path: Path,
    compat_cfg: dict,
    options: CompatOptions,
    core_version: str | None,
) -> CoreTester:
    if options.tester_factory is not None:
        return options.tester_factory(core, binary_path, compat_cfg, _parse_test_urls(compat_cfg))
    builder, writer, argv, port_getter = BUILDERS[core]
    return CoreTester(
        core=core,
        binary_path=binary_path,
        config_builder=builder,
        config_writer=writer,
        argv_builder=argv,
        port_getter=port_getter,
        test_urls=_parse_test_urls(compat_cfg),
        startup_timeout=float(compat_cfg["startup_timeout_seconds"]),
        http_timeout=float(compat_cfg["http_timeout_seconds"]),
        core_version=core_version,
    )


def _parse_test_urls(compat_cfg: dict) -> list[CompatTestUrl]:
    urls: list[CompatTestUrl] = []
    for entry in compat_cfg["test_urls"]:
        expect = tuple(int(s) for s in entry.get("expect_status", [200, 204]))
        urls.append(CompatTestUrl(
            url=str(entry["url"]),
            expect_statuses=expect,
            expect_substring=entry.get("expect_substring"),
        ))
    return urls


def _entry_latency(entry: dict) -> float | None:
    value = entry.get("proxy_latency_ms")
    return float(value) if isinstance(value, (int, float)) else None


def detect_core_version(core: str, binary_path: Path) -> str | None:
    """Ask the binary for its version string (bounded, credential-free)."""
    argv = {
        "singbox": [str(binary_path), "version"],
        "xray": [str(binary_path), "version"],
        "hiddify": [str(binary_path), "version"],
        "mihomo": [str(binary_path), "-v"],
    }.get(core)
    if not argv:
        return None
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (completed.stdout or completed.stderr or "").strip()
    first_line = redact_stderr(output.encode("utf-8", "ignore")).splitlines()[0] if output else ""
    return first_line[:120] or None


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return round(ordered[mid], 1)
    return round((ordered[mid - 1] + ordered[mid]) / 2.0, 1)
