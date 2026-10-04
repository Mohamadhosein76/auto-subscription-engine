"""Live connectivity pipeline backed by the Stage 5 verification engine.

Stages (all bounded, failure-isolated, deterministic where required):

1. structural discovery/ingestion/validation/deduplication
2. Stage 4 direct-IP expansion from bounded DNS evidence/history
3. persistent adaptive preflight scheduling (exploration/recovery/direct-IP/source intelligence)
4. endpoint preflight — DNS/address visibility plus TCP diagnostics where relevant
5. persistent adaptive runtime scheduling from preflight survivors
6. native runtime verification — pinned sing-box, repeated required HTTP/HTTPS quorum
7. history update + endpoint geolocation telemetry
8. scoring / ranking / diversity-aware selection
9. outputs — live subscription, metadata, stats, diagnostics, countries

Hostname configs remain hostnames during runtime verification. Resolver IPs are
diagnostic only; genuine direct-IP configs are separate Stage 4 candidates.
The pipeline FAILS (raises :class:`SystemicPipelineError`) only for systemic
problems. Individual node failures remain isolated.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ..network.geo import GeoInfo, GeoResolver, GeoSettings
from ..scheduling import CandidateScheduler, ReliabilityHistory, policy_from_mapping
from ..discovery import SourceIntelligenceStore
from ..models import (
    ParsedConfig,
    SourceConfigError,
    canonical_to_legacy,
    legacy_to_canonical,
)
from ..models.fingerprint import normalize_config
from ..models.validation import validate_config
from ..network import StaticIpHunter, is_ip_literal
from ..clients.install import specs_from_testing_config, verified_core_paths
from ..verification import (
    NodeVerificationResult,
    VerificationEngine,
    VerificationPolicy,
    median,
)
from ..serialization import to_share_uri
from .pipeline import RunOptions, collect_configs
from ..utils.identity import config_safe_id
from ..scoring import (
    ScoringPolicy,
    apply_preselection_scores,
    rank_live,
    select_diverse,
)
from ..security.config import DEFAULT_SECURITY_CONFIG

logger = logging.getLogger(__name__)


class SystemicPipelineError(Exception):
    """Raised only for systemic failures that should fail the whole run."""


#: Conservative defaults for GitHub-hosted runners; overridable via
#: ``config/testing.yaml``. No secret values here — safe to publish.
DEFAULT_TESTING_CONFIG: dict = {
    "singbox": {
        "version": "1.14.2",
        "archive_sha256": "a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6",
        "url_template": (
            "https://github.com/SagerNet/sing-box/releases/download/"
            "v{version}/sing-box-{version}-linux-amd64.tar.gz"
        ),
        "archive_binary_path": "sing-box-{version}-linux-amd64/sing-box",
    },
    "verification": {
        "connect_timeout_seconds": 3.0,
        "preflight_concurrency": 200,
        "max_addresses_per_node": 6,
        "runtime_concurrency": 10,
        "startup_timeout_seconds": 5.0,
        "http_timeout_seconds": 8.0,
        "repetitions": 2,
        "min_success_ratio": 0.66,
        "min_success_count": 4,
        "min_round_success_ratio": 0.5,
        "soft_deadline_seconds": 600.0,
        "max_body_bytes": 65536,
        "targets": [
            {"url": "https://www.gstatic.com/generate_204", "expect_status": [200, 204], "kind": "egress"},
            {"url": "https://www.msftconnecttest.com/connecttest.txt", "expect_status": [200], "expect_substring": "Microsoft", "kind": "egress"},
            {"url": "https://example.com/", "expect_status": [200], "expect_substring": "Example Domain", "kind": "egress"},
            {"url": "https://dns.google/resolve?name=example.com&type=A", "expect_status": [200], "expect_substring": "Status", "kind": "doh", "required": False},
        ],
    },
    "scheduler": {
        "preflight_budget": 1500,
        "runtime_budget": 400,
        "exploration_share": 0.35,
        "recovery_share": 0.20,
        "direct_ip_share": 0.15,
        "source_base_share": 0.15,
        "source_quality_bonus_share": 0.20,
        "healthy_retest_minutes": 180,
        "flaky_retest_minutes": 45,
        "exploration_retry_minutes": 60,
        "recovery_base_minutes": 30,
        "recovery_max_hours": 12,
        "stale_after_hours": 24,
        "flaky_success_rate": 0.75,
        "source_quality_weight": 20.0,
        "direct_ip_bonus": 12.0,
        "preflight_latency_bonus": 10.0,
        "allow_early_fill": True,
    },
    "geo": {
        "batch_url": "http://ip-api.com/batch?fields=status,country,countryCode,query",
        "single_url": "http://ip-api.com/json/{ip}?fields=status,country,countryCode",
        "timeout_seconds": 5.0,
        "batch_size": 100,
        "batch_rate_per_minute": 15,
        "max_lookups": 1000,
    },
    "scoring": {
        "preselection_weights": {
            "connectivity": 35.0,
            "latency": 25.0,
            "reliability": 25.0,
            "stability": 15.0,
        },
        "global_weights": {
            "connectivity": 30.0,
            "latency": 20.0,
            "reliability": 25.0,
            "freshness": 10.0,
            "security": 15.0,
        },
        "operator_weights": {
            "connectivity": 45.0,
            "reliability": 30.0,
            "latency": 15.0,
            "freshness": 10.0,
        },
        "client_weights": {
            "runtime": 60.0,
            "reliability": 20.0,
            "latency": 20.0,
        },
        "latency_min_ms": 150.0,
        "latency_max_ms": 3000.0,
        "min_history_samples": 3,
        "freshness_full_minutes": 60,
        "freshness_zero_minutes": 1440,
    },
    "selection": {
        "max_live_nodes": 300,
        "per_host_limit": 3,
    },
    # Task 3: bounded, committed reliability history (data/history.json).
    "history": {
        "retention_days": 30,
        "max_entries": 50000,
    },
    # Task 3: guarded publishing to public/ (committed to main).
    "publish": {
        "min_live_nodes": 5,
        "max_drop_ratio": 0.80,
    },
    # Task 4: Security Intelligence Layer defaults (see security/config.py
    # for the full, documented structure). config/testing.yaml overrides.
    "security": DEFAULT_SECURITY_CONFIG,
}

#: Failure reasons that are *not* the node's fault; excluded from history.
_NON_NODE_FAILURE_PREFIXES = ("internal_error", "stage_deadline")


@dataclass
class LiveOptions:
    """Options for one live pipeline run."""

    config_path: Path
    testing_config_path: Path
    output_dir: Path
    core_dir: Path = Path(".core-bin")
    core_paths: dict[str, Path] | None = None
    history_path: Path | None = None
    discovery_config_path: Path | None = Path("config/discovery.yaml")
    discovery_state_path: Path | None = Path("data/discovery.json")
    ip_hunter_config_path: Path | None = None
    ip_history_path: Path | None = None
    from_file: Path | None = None
    timeout: float = 15.0
    retries: int = 2
    preflight_budget: int | None = None
    runtime_budget: int | None = None
    max_live_nodes: int | None = None


def load_testing_config(path: Path) -> dict:
    """Load config/testing.yaml and merge it over the conservative defaults."""
    merged = json.loads(json.dumps(DEFAULT_TESTING_CONFIG))  # deep copy
    if path is not None and Path(path).is_file():
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise SystemicPipelineError(f"cannot read testing config {path}: {exc}") from exc
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise SystemicPipelineError("testing config must be a YAML mapping")
        for section, values in raw.items():
            if isinstance(values, dict) and isinstance(merged.get(section), dict):
                merged[section].update(values)
            else:
                merged[section] = values
    _validate_testing_config(merged)
    return merged


def _validate_testing_config(cfg: dict) -> None:
    try:
        ScoringPolicy.from_mapping(cfg.get("scoring", {}))
        VerificationPolicy.from_mapping(cfg.get("verification", {}))
        policy_from_mapping(cfg.get("scheduler", {}))
    except ValueError as exc:
        raise SystemicPipelineError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def run_live_pipeline(options: LiveOptions) -> dict:
    """Run the full live pipeline and return the stats mapping."""
    started = time.monotonic()
    tc = load_testing_config(options.testing_config_path)

    core_paths = dict(options.core_paths or verified_core_paths(options.core_dir, tc))
    if not core_paths:
        raise SystemicPipelineError(
            f"no checksum-verified proxy core found in {options.core_dir} — "
            "run cores-install first"
        )

    # -- structural stage (Task 1 reuse) ------------------------------------
    run_options = RunOptions(
        config_path=options.config_path,
        output_dir=options.output_dir,
        timeout=options.timeout,
        retries=options.retries,
        from_file=options.from_file,
        discovery_config_path=options.discovery_config_path,
        discovery_state_path=options.discovery_state_path,
    )
    try:
        configs, structural_stats = collect_configs(run_options)
    except SourceConfigError as exc:
        raise SystemicPipelineError(str(exc)) from exc
    if options.from_file is None and structural_stats["sources_success"] == 0:
        raise SystemicPipelineError("no source could be fetched — systemic failure")

    scheduler_policy = policy_from_mapping(tc.get("scheduler", {}))
    preflight_budget = int(
        scheduler_policy.preflight_budget if options.preflight_budget is None else options.preflight_budget
    )
    runtime_budget = int(
        scheduler_policy.runtime_budget if options.runtime_budget is None else options.runtime_budget
    )
    if preflight_budget <= 0 or runtime_budget <= 0:
        raise SystemicPipelineError("scheduler budget overrides must be positive")
    max_live_nodes = int(
        options.max_live_nodes or tc["selection"]["max_live_nodes"]
    )
    per_host_limit = int(tc["selection"]["per_host_limit"])

    # Stage 6 candidate intelligence is loaded before any sampling.  Every
    # discovered fingerprint is observed so never-tested pools rotate between
    # runs instead of repeatedly selecting the same deterministic prefix.
    history = ReliabilityHistory.load(options.history_path)
    discovery_state = SourceIntelligenceStore.load(options.discovery_state_path)
    scheduler = CandidateScheduler(
        policy=scheduler_policy,
        history=history,
        source_quality=discovery_state.quality_by_name(),
    )
    seed_plan = scheduler.plan_preflight(configs, budget=preflight_budget)
    base_candidates = list(seed_plan.selected)

    # -- Stage A0: bounded direct-IP expansion --------------------------------
    # The hunter never scans arbitrary address space. It only resolves hostnames
    # selected by the adaptive scheduler, then creates semantically equivalent
    # IP-pinned variants while preserving SNI/HTTP Host/Reality.
    candidates = list(base_candidates)
    ip_hunter_stats: dict[str, object] = {
        "enabled": False,
        "variants_created": 0,
    }
    if options.ip_hunter_config_path is not None:
        try:
            hunter = StaticIpHunter.from_paths(
                config_path=options.ip_hunter_config_path,
                history_path=options.ip_history_path,
            )
            canonical_inputs = [legacy_to_canonical(config) for config in base_candidates]
            hunted = hunter.hunt(canonical_inputs)
            ip_hunter_stats = {"enabled": hunter.policy.enabled, **hunted.to_stats()}
            existing = {config.fingerprint for config in candidates}
            for canonical in hunted.variants:
                try:
                    uri = to_share_uri(canonical)
                    variant = canonical_to_legacy(canonical, original_uri=uri)
                    variant = normalize_config(variant)
                    if variant.fingerprint in existing:
                        continue
                    verdict = validate_config(variant)
                    if not verdict.ok:
                        continue
                    candidates.append(variant)
                    existing.add(variant.fingerprint)
                except Exception as exc:
                    logger.debug("IP hunter variant rejected: %s", type(exc).__name__)
        except (OSError, ValueError) as exc:
            raise SystemicPipelineError(f"cannot run static-IP hunter: {exc}") from exc

    # Static-IP variants receive the same scheduler treatment as domain inputs.
    # Re-planning keeps the preflight safety ceiling intact while reserving room
    # for direct-IP exploration; only the final plan is marked as scheduled.
    preflight_plan = scheduler.plan_preflight(candidates, budget=preflight_budget)
    candidates = list(preflight_plan.selected)
    scheduler.mark_selected(preflight_plan)

    # -- Stage A/B: central verification engine -------------------------------
    # Cheap endpoint preflight is diagnostic only. Runtime verification is the
    # liveness source of truth. UDP-native protocols are never rejected because
    # their TCP port is closed, and hostname configs are runtime-tested using
    # the original hostname rather than a GitHub-resolved IP.
    try:
        verification_policy = VerificationPolicy.from_mapping(tc.get("verification", {}))
    except ValueError as exc:
        raise SystemicPipelineError(str(exc)) from exc
    verifier = VerificationEngine(core_paths, verification_policy)
    preflight_results = verifier.preflight(candidates)
    preflight_passed = [r for r in preflight_results if r.preflight_success]
    preflight_failure_reasons = dict(
        sorted(Counter(
            r.failure_reason or "unknown"
            for r in preflight_results
            if not r.preflight_success
        ).items())
    )

    # Runtime scheduling is independent from preflight scheduling. A candidate
    # that repeatedly survives cheap preflight but has never received runtime
    # budget gets a persistent promotion on subsequent runs.
    runtime_plan = scheduler.plan_runtime(preflight_passed, budget=runtime_budget)
    runtime_candidates = list(runtime_plan.selected)
    scheduler.mark_selected(runtime_plan)
    runtime_results, not_tested = verifier.runtime(runtime_candidates)
    live_results = [r for r in runtime_results if r.passed]
    runtime_failure_reasons = dict(
        sorted(Counter(
            (r.failure_reason or "unknown").split(":")[0]
            for r in runtime_results
            if not r.passed
        ).items())
    )

    # -- reliability history ----------------------------------------------------
    # Only an actual endpoint failure or runtime failure affects reliability.
    # UDP-native configs that merely skip TCP probing are not punished.
    for preflight in preflight_results:
        if not preflight.preflight_success:
            history.record(preflight.config.fingerprint, passed=False)
    for runtime in runtime_results:
        if runtime.passed:
            history.record(
                runtime.config.fingerprint,
                passed=True,
                latency_ms=runtime.proxy_latency_ms,
            )
        elif not _is_non_node_failure(runtime.failure_reason):
            history.record(runtime.config.fingerprint, passed=False)

    # -- node results ------------------------------------------------------------
    preflight_by_fp = {r.config.fingerprint: r for r in preflight_results}
    runtime_by_fp = {r.config.fingerprint: r for r in runtime_results}
    nodes: dict[str, NodeVerificationResult] = {}
    for config in candidates:
        nodes[config.fingerprint] = NodeVerificationResult(
            config=config,
            preflight=preflight_by_fp.get(config.fingerprint),
            runtime=runtime_by_fp.get(config.fingerprint),
        )
    live_nodes = [nodes[fp] for fp in sorted(nodes) if nodes[fp].status == "live"]

    # -- country detection (endpoint IP based, cached, capped) --------------------
    geo_settings = GeoSettings(
        batch_url=tc["geo"]["batch_url"],
        single_url=tc["geo"]["single_url"],
        timeout_seconds=float(tc["geo"]["timeout_seconds"]),
        batch_size=int(tc["geo"]["batch_size"]),
        batch_rate_per_minute=int(tc["geo"]["batch_rate_per_minute"]),
        max_lookups=int(tc["geo"]["max_lookups"]),
    )
    resolver = GeoResolver(geo_settings)
    endpoint_ips = sorted({
        node.tcp.resolved_ip or (node.config.host or "")
        for node in live_nodes
        if node.tcp is not None
    })
    try:
        geo_map: dict[str, GeoInfo] = resolver.lookup_many(endpoint_ips)
    except Exception as exc:  # defensive: geo failures never kill the run
        logger.warning("country detection failed entirely: %s", type(exc).__name__)
        geo_map = {}
    for node in live_nodes:
        ip = node.tcp.resolved_ip or (node.config.host or "") if node.tcp else ""
        info = geo_map.get(ip or "", GeoInfo())
        node.country_code = info.country_code
        node.country_name = info.country_name

    # -- scoring / ranking / selection ---------------------------------------------
    scoring_policy = ScoringPolicy.from_mapping(tc.get("scoring", {}))
    apply_preselection_scores(live_nodes, history, scoring_policy)
    ranked = rank_live(live_nodes)
    selected = select_diverse(
        ranked, max_live_nodes=max_live_nodes, per_host_limit=per_host_limit
    )
    selected_fps = {node.config.fingerprint for node in selected}

    # -- per-source quality recording (persisted for the next run) ------------
    _record_discovery_quality(discovery_state, candidates, preflight_results, runtime_results, selected)

    # -- bounded history persistence -----------------------------------------------
    try:
        history_cfg = tc.get("history", {})
        history.prune(
            retention_days=int(history_cfg.get("retention_days", 30)),
            max_entries=int(history_cfg.get("max_entries", 50000)),
        )
        history.save(options.history_path)
    except OSError as exc:
        raise SystemicPipelineError(f"cannot persist history: {exc}") from exc
    try:
        discovery_state.save(options.discovery_state_path)
    except OSError as exc:
        raise SystemicPipelineError(f"cannot persist discovery intelligence: {exc}") from exc

    # -- stats ------------------------------------------------------------------------
    runtime_seconds = time.monotonic() - started
    median_tcp = median([
        r.tcp_latency_ms for r in preflight_results
        if r.tcp_latency_ms is not None
    ] or [])
    median_proxy = median([
        r.proxy_latency_ms for r in live_results
        if r.proxy_latency_ms is not None
    ] or [])
    count_by_country = dict(sorted(
        Counter(node.country_code for node in selected).items()
    ))
    count_by_protocol_live = dict(sorted(
        Counter(node.config.protocol for node in selected).items()
    ))
    countries_discovered = len({
        node.country_code for node in live_nodes if node.country_code != "UNKNOWN"
    })
    runtime_core_counts = dict(sorted(Counter(
        result.runtime_core for result in live_results if result.runtime_core
    ).items()))
    pinned_specs = specs_from_testing_config(tc)
    runtime_core_versions = {
        key: pinned_specs[key].version
        for key in sorted(core_paths)
        if key in pinned_specs
    }

    stats: dict[str, object] = dict(structural_stats)
    stats.update({
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "pipeline": "live-connectivity",
        "base_candidates_sampled": len(base_candidates),
        "scheduler": {
            "seed": seed_plan.summary(),
            "preflight": preflight_plan.summary(),
            "runtime": runtime_plan.summary(),
        },
        "candidates_sampled": len(candidates),
        "ip_hunter": ip_hunter_stats,
        # Legacy field names stay in the public contract while Stage 5 adds
        # explicit verification vocabulary beside them.
        "tcp_tested": len(preflight_results),
        "tcp_passed": len(preflight_passed),
        "tcp_failure_reasons": preflight_failure_reasons,
        "preflight_tested": len(preflight_results),
        "preflight_passed": len(preflight_passed),
        "preflight_failure_reasons": preflight_failure_reasons,
        "proxy_candidates": len(runtime_candidates),
        "proxy_tested": len(runtime_results),
        "proxy_not_tested": not_tested,
        "proxy_live": len(live_results),
        "proxy_failure_reasons": runtime_failure_reasons,
        "runtime_candidates": len(runtime_candidates),
        "runtime_tested": len(runtime_results),
        "runtime_not_tested": not_tested,
        "runtime_live": len(live_results),
        "runtime_failure_reasons": runtime_failure_reasons,
        "runtime_core_counts": runtime_core_counts,
        "runtime_cores_available": sorted(core_paths),
        "live_total": len(live_nodes),
        "live_selected": len(selected),
        "median_tcp_latency_ms": round(median_tcp, 1) if median_tcp is not None else None,
        "median_proxy_latency_ms": round(median_proxy, 1) if median_proxy is not None else None,
        "countries_discovered": countries_discovered,
        "count_by_country": count_by_country,
        "count_by_protocol_live": count_by_protocol_live,
        "runtime_seconds": round(runtime_seconds, 1),
        "status": "ok" if selected else "zero_live",
        "history_entries": len(history.entries),
        "effective_config": {
            "preflight_budget": preflight_budget,
            "runtime_budget": runtime_budget,
            "max_live_nodes": max_live_nodes,
            "per_host_limit": per_host_limit,
            "tcp_concurrency": verification_policy.preflight_concurrency,
            "proxy_concurrency": verification_policy.runtime_concurrency,
            "preflight_concurrency": verification_policy.preflight_concurrency,
            "runtime_concurrency": verification_policy.runtime_concurrency,
            "verification_repetitions": verification_policy.repetitions,
            "verification_min_success_ratio": verification_policy.min_success_ratio,
            "verification_min_success_count": verification_policy.min_success_count,
            "verification_min_round_success_ratio": verification_policy.min_round_success_ratio,
            "core_version": "multi-core:" + ",".join(
                f"{key}={version}" for key, version in runtime_core_versions.items()
            ),
            "core_versions": runtime_core_versions,
        },
    })

    # -- outputs -------------------------------------------------------------------------
    try:
        _write_live_outputs(options.output_dir, ranked, selected, selected_fps, stats)
    except OSError as exc:
        raise SystemicPipelineError(f"cannot write live outputs: {exc}") from exc

    logger.info(
        "live pipeline complete: sampled=%d preflight_passed=%d proxy_live=%d selected=%d "
        "(runtime %.1fs)",
        len(candidates),
        len(preflight_passed),
        len(live_results),
        len(selected),
        runtime_seconds,
    )
    if not selected:
        logger.warning(
            "zero LIVE nodes found — outputs and diagnostics were still written"
        )
    return stats


def _is_non_node_failure(reason: str | None) -> bool:
    """True for failures that must not punish the node in history."""
    if not reason:
        return True
    return reason.startswith(_NON_NODE_FAILURE_PREFIXES)


def _record_discovery_quality(
    store: SourceIntelligenceStore,
    candidates: list,
    preflight_results: list,
    runtime_results: list,
    selected: list,
) -> None:
    """Feed connectivity outcomes back into the Stage 3 source model."""
    per_tcp_tested: Counter[str] = Counter(
        (r.config.source or "") for r in preflight_results if (r.config.source or "")
    )
    per_preflight_passed: Counter[str] = Counter(
        (r.config.source or "") for r in preflight_results
        if r.preflight_success and (r.config.source or "")
    )
    per_proxy_tested: Counter[str] = Counter(
        (r.config.source or "") for r in runtime_results if (r.config.source or "")
    )
    per_proxy_passed: Counter[str] = Counter(
        (r.config.source or "") for r in runtime_results
        if r.passed and (r.config.source or "")
    )
    per_published: Counter[str] = Counter(
        (node.config.source or "") for node in selected if (node.config.source or "")
    )
    names = set(per_tcp_tested) | set(per_proxy_tested) | set(per_published)
    for name in sorted(names):
        store.record_verification_by_name(
            name,
            tcp_tested=per_tcp_tested[name],
            tcp_passed=per_preflight_passed[name],
            proxy_tested=per_proxy_tested[name],
            proxy_passed=per_proxy_passed[name],
            published=per_published[name],
        )


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------


def _write_live_outputs(
    output_dir: Path,
    ranked: list[NodeVerificationResult],
    selected: list[NodeVerificationResult],
    selected_fps: set[str],
    stats: dict[str, object],
) -> None:
    """Write deterministic live-verification outputs."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ranked_uris = [node.config.original_uri for node in ranked]
    ranked_body = "\n".join(ranked_uris) + ("\n" if ranked_uris else "")
    (output_dir / "live_subscription.txt").write_text(ranked_body, encoding="utf-8", newline="\n")
    encoded = base64.b64encode(ranked_body.encode("utf-8")).decode("ascii")
    (output_dir / "live_subscription_base64.txt").write_text(encoded + "\n", encoding="ascii", newline="\n")

    best_uris = [node.config.original_uri for node in selected]
    best_body = "\n".join(best_uris) + ("\n" if best_uris else "")
    (output_dir / "best.txt").write_text(best_body, encoding="utf-8", newline="\n")

    nodes_payload = []
    for node in ranked:
        proxy = node.proxy
        nodes_payload.append({
            "safe_id": config_safe_id(node.config),
            "protocol": node.config.protocol,
            "status": node.status,
            "selected": node.config.fingerprint in selected_fps,
            "country_code": node.country_code,
            "country_name": node.country_name,
            # Downstream runtime stages must not pin hostname nodes to the
            # resolver result observed on this runner. Only genuine direct-IP
            # configs expose resolved_ip; hostname resolution stays diagnostic.
            "resolved_ip": (
                node.config.host if node.config.host and is_ip_literal(node.config.host) else None
            ),
            "preflight_resolved_ip": node.preflight.resolved_ip if node.preflight else None,
            "tcp_latency_ms": (
                round(node.tcp.tcp_latency_ms, 1)
                if node.tcp and node.tcp.tcp_latency_ms is not None else None
            ),
            "proxy_latency_ms": (
                round(proxy.proxy_latency_ms, 1)
                if proxy and proxy.proxy_latency_ms is not None else None
            ),
            "success_ratio": round(proxy.success_ratio, 3) if proxy else 0.0,
            "runtime_core": proxy.runtime_core if proxy else None,
            "verification": {
                "transport": node.preflight.transport if node.preflight else None,
                "resolved_ips": list(node.preflight.resolved_ips) if node.preflight else [],
                "ipv4_preflight": node.preflight.ipv4_success if node.preflight else False,
                "ipv6_preflight": node.preflight.ipv6_success if node.preflight else False,
                "mode": proxy.mode if proxy else None,
                "runtime_core": proxy.runtime_core if proxy else None,
                "attempted_cores": list(proxy.attempted_cores) if proxy else [],
                "success_count": proxy.success_count if proxy else 0,
                "latency_p95_ms": (
                    round(proxy.latency_p95_ms, 1)
                    if proxy and proxy.latency_p95_ms is not None else None
                ),
                "jitter_ms": (
                    round(proxy.jitter_ms, 1)
                    if proxy and proxy.jitter_ms is not None else None
                ),
            },
            "score": node.score,
            "source": node.config.source or "",
        })
    (output_dir / "live_nodes.json").write_text(
        json.dumps(nodes_payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",newline="\n"
    )
    (output_dir / "live_stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",newline="\n"
    )

    diagnostics = {
        "tcp_failure_reasons": stats.get("tcp_failure_reasons", stats.get("preflight_failure_reasons", {})),
        "proxy_failure_reasons": stats.get("proxy_failure_reasons", stats.get("runtime_failure_reasons", {})),
        "preflight_failure_reasons": stats.get("preflight_failure_reasons", stats.get("tcp_failure_reasons", {})),
        "runtime_failure_reasons": stats.get("runtime_failure_reasons", stats.get("proxy_failure_reasons", {})),
        "proxy_not_tested": stats.get("proxy_not_tested", stats.get("runtime_not_tested", 0)),
        "zero_live": not selected,
        "note": "all values are credential-free aggregate counters",
    }
    (output_dir / "live_diagnostics.json").write_text(
        json.dumps(diagnostics, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",newline="\n"
    )

    countries_dir = output_dir / "countries"
    countries_dir.mkdir(exist_ok=True)
    by_country: dict[str, list[str]] = {}
    for node in selected:
        by_country.setdefault(node.country_code, []).append(node.config.original_uri)
    for code, uris in sorted(by_country.items()):
        (countries_dir / f"{code}.txt").write_text(
            "\n".join(uris) + "\n", encoding="utf-8", newline="\n"
        )


# ---------------------------------------------------------------------------
# Output verification (CLI: verify-live)
# ---------------------------------------------------------------------------

_REQUIRED_LIVE_FILES = (
    "live_subscription.txt",
    "live_subscription_base64.txt",
    "live_nodes.json",
    "live_stats.json",
    "best.txt",
)

_REQUIRED_NODE_KEYS = {
    "safe_id",
    "protocol",
    "status",
    "country_code",
    "country_name",
    "resolved_ip",
    "tcp_latency_ms",
    "proxy_latency_ms",
    "success_ratio",
    "score",
}

_FORBIDDEN_NODE_KEYS = {"original_uri", "uri", "uuid", "password", "identity", "params"}

_REQUIRED_STATS_KEYS = (
    "configs_received",
    "final_configs",
    "candidates_sampled",
    "tcp_tested",
    "tcp_passed",
    "proxy_tested",
    "proxy_live",
    "live_selected",
    "status",
    "runtime_seconds",
)


def verify_live_outputs(output_dir: Path) -> list[str]:
    """Validate the Task 2 outputs; return a list of problems (empty = valid)."""
    problems: list[str] = []
    output_dir = Path(output_dir)
    if not output_dir.is_dir():
        return [f"output directory not found: {output_dir}"]

    for name in _REQUIRED_LIVE_FILES:
        if not (output_dir / name).is_file():
            problems.append(f"missing file: {name}")
    if problems:
        return problems

    text = (output_dir / "live_subscription.txt").read_text(encoding="utf-8")
    try:
        encoded = (output_dir / "live_subscription_base64.txt").read_text(
            encoding="ascii"
        ).strip()
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        if decoded != text:
            problems.append("live base64 content does not match live_subscription.txt")
    except (ValueError, UnicodeDecodeError):
        problems.append("live_subscription_base64.txt is not valid base64")

    try:
        nodes = json.loads((output_dir / "live_nodes.json").read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        problems.append("live_nodes.json is not valid JSON")
        return problems
    if not isinstance(nodes, list):
        problems.append("live_nodes.json must contain a JSON array")
        return problems

    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            problems.append(f"live_nodes.json entry {index} is not an object")
            continue
        missing = _REQUIRED_NODE_KEYS - set(node)
        if missing:
            problems.append(f"live_nodes.json entry {index} missing keys: {sorted(missing)}")
        forbidden = _FORBIDDEN_NODE_KEYS & set(node)
        if forbidden:
            problems.append(
                f"live_nodes.json entry {index} leaks sensitive keys: {sorted(forbidden)}"
            )

    try:
        stats = json.loads((output_dir / "live_stats.json").read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        problems.append("live_stats.json is not valid JSON")
        return problems
    if not isinstance(stats, dict):
        problems.append("live_stats.json must contain a JSON object")
        return problems
    for key in _REQUIRED_STATS_KEYS:
        if key not in stats:
            problems.append(f"live_stats.json is missing key: {key}")

    best_lines = [
        line for line in
        (output_dir / "best.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    live_selected = stats.get("live_selected")
    if isinstance(live_selected, int) and live_selected != len(best_lines):
        problems.append(
            f"live_stats.json live_selected ({live_selected}) != best.txt lines ({len(best_lines)})"
        )

    selected_entries = [n for n in nodes if isinstance(n, dict) and n.get("selected")]
    if isinstance(live_selected, int) and live_selected != len(selected_entries):
        problems.append(
            f"live_selected ({live_selected}) != selected entries in live_nodes.json ({len(selected_entries)})"
        )

    countries_dir = output_dir / "countries"
    if countries_dir.is_dir():
        country_files = {p.stem for p in countries_dir.glob("*.txt")}
        by_country = stats.get("count_by_country")
        if isinstance(by_country, dict):
            if country_files != set(by_country):
                problems.append(
                    "countries/ directory does not match live_stats.json count_by_country"
                )
        else:
            problems.append("live_stats.json count_by_country must be a mapping")

    return problems
