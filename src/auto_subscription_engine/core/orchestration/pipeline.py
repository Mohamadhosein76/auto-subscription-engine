"""Structural pipeline backed by the central canonical ingestion/discovery core.

Stage 3 removes the legacy source/fetch path completely. Both local content and
remote sources now enter through ``core.ingestion`` and ``core.discovery`` so
there is one parsing source of truth and one source-discovery implementation.
"""
from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..discovery import DiscoveryEngine, load_discovery_policy
from ..ingestion import ingest_content
from ..models import SourceConfigError, canonical_to_legacy
from ..serialization import to_share_uri
from ..models.dedup import canonical_order, deduplicate
from ..models.fingerprint import normalize_config
from .output import write_outputs
from ..models.validation import validate_config

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RunOptions:
    """Options for a single structural pipeline run."""

    config_path: Path
    output_dir: Path
    timeout: float = 15.0
    retries: int = 2
    from_file: Path | None = None
    discovery_config_path: Path | None = Path("config/discovery.yaml")
    discovery_state_path: Path | None = None


def collect_configs(options: RunOptions):
    """Ingest, validate and deduplicate configurations without writing output."""
    source_reports: list[dict[str, object]] = []
    discovery_duplicates = 0
    ingestion_issues: list[str] = []

    if options.from_file is not None:
        raw = _read_local(options.from_file)
        ingestion = ingest_content(raw, source="")
        canonical_configs = ingestion.proxies
        ingestion_issues = [issue.reason for issue in ingestion.issues]
        configs_received = len(canonical_configs) + len(ingestion.issues)
        logger.info(
            "offline mode: %d parsed candidates (%d ingestion issues) loaded from %s",
            len(canonical_configs),
            len(ingestion.issues),
            options.from_file,
        )
        mode = "offline"
        discovery_summary: dict[str, object] = {
            "nested_sources_discovered": len(ingestion.nested_sources),
            "sources_quarantined": 0,
            "duplicates_removed_during_discovery": 0,
        }
    else:
        policy = load_discovery_policy(options.discovery_config_path)
        engine = DiscoveryEngine.from_config(
            options.config_path,
            policy=policy,
            state_path=options.discovery_state_path,
            timeout=options.timeout,
            retries=options.retries,
        )
        discovered = engine.discover()
        canonical_configs = discovered.proxies
        discovery_duplicates = discovered.duplicates_removed
        configs_received = sum(
            report.proxies_found + report.issues for report in discovered.reports
        )
        ingestion_issues = [
            "discovery source failed"
            for report in discovered.reports
            if not report.ok and report.skipped_reason is None
        ]
        source_reports = [_source_report_dict(report) for report in discovered.reports]
        mode = "discovery"
        discovery_summary = {
            "nested_sources_discovered": len(discovered.nested_sources),
            "sources_fetched": discovered.sources_fetched,
            "sources_quarantined": discovered.sources_quarantined,
            "duplicates_removed_during_discovery": discovery_duplicates,
        }

    valid_configs = []
    invalid_count = 0
    unknown_count = 0
    reasons: Counter[str] = Counter()

    for reason in ingestion_issues:
        if "unsupported scheme" in reason or "unsupported" in reason and "protocol" in reason:
            unknown_count += 1
            reasons["unknown protocol"] += 1
        elif reason == "discovery source failed":
            # Source failure belongs in source diagnostics, not config validity.
            continue
        else:
            invalid_count += 1
            reasons[f"parse: {reason}"] += 1

    for canonical in canonical_configs:
        try:
            uri = canonical.raw or to_share_uri(canonical)
            config = canonical_to_legacy(canonical, original_uri=uri)
            config = normalize_config(config)
        except Exception as exc:  # defensive: malformed structured adapter output
            invalid_count += 1
            reasons[f"normalize: {type(exc).__name__}"] += 1
            continue
        verdict = validate_config(config)
        if verdict.ok:
            valid_configs.append(config)
        else:
            invalid_count += 1
            reasons[f"validate: {verdict.reason}"] += 1

    final_configs, legacy_duplicates = deduplicate(valid_configs)
    final_configs = canonical_order(final_configs)
    duplicates_removed = discovery_duplicates + legacy_duplicates

    sources_total = len(source_reports)
    sources_success = sum(1 for report in source_reports if report["ok"])
    sources_failed = sum(
        1
        for report in source_reports
        if not report["ok"] and report.get("skipped_reason") is None
    )
    # Quarantined/skipped sources are neither successes nor failures; they
    # are counted separately so sources_total reconciles exactly.
    sources_skipped = sum(
        1
        for report in source_reports
        if not report["ok"] and report.get("skipped_reason") is not None
    )

    stats: dict[str, object] = {
        "mode": mode,
        "sources_total": sources_total,
        "sources_success": sources_success,
        "sources_failed": sources_failed,
        "sources_skipped": sources_skipped,
        "configs_received": configs_received,
        "configs_unknown_protocol": unknown_count,
        "configs_invalid": invalid_count,
        "configs_valid": len(valid_configs),
        # Discovery-stage duplicates never entered valid_configs (they are
        # dropped before validation), so only dedup-stage removals may be
        # subtracted from configs_valid to reconcile with final_configs.
        "duplicates_removed_during_dedup": legacy_duplicates,
        "duplicates_removed": duplicates_removed,
        "final_configs": len(final_configs),
        "count_by_protocol": dict(sorted(Counter(c.protocol for c in final_configs).items())),
        "invalid_reasons": dict(sorted(reasons.items())),
        "sources": source_reports,
        "discovery": discovery_summary,
    }
    return final_configs, stats


def run_pipeline(options: RunOptions) -> dict:
    final_configs, stats = collect_configs(options)
    stats["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    write_outputs(final_configs, stats, options.output_dir)
    logger.info(
        "pipeline complete: received=%d unknown=%d invalid=%d valid=%d duplicates_removed=%d final=%d",
        stats["configs_received"],
        stats["configs_unknown_protocol"],
        stats["configs_invalid"],
        stats["configs_valid"],
        stats["duplicates_removed"],
        stats["final_configs"],
    )
    return stats


def _source_report_dict(report) -> dict[str, object]:
    payload = asdict(report)
    # Keep the public diagnostics credential-free: discovery state/reporting
    # never exposes the source URL or query string.
    payload["uri_count"] = payload.pop("proxies_found")
    return payload


def _read_local(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SourceConfigError(f"cannot read input file {path}: {exc}") from exc


def summarize(stats: Mapping[str, object]) -> Sequence[str]:
    return [
        f"sources: {stats['sources_success']}/{stats['sources_total']} succeeded",
        f"configs received: {stats['configs_received']}",
        f"configs valid: {stats['configs_valid']} "
        f"(unknown protocol: {stats['configs_unknown_protocol']}, invalid: {stats['configs_invalid']})",
        f"duplicates removed: {stats['duplicates_removed']}",
        f"final configs: {stats['final_configs']}",
    ]
