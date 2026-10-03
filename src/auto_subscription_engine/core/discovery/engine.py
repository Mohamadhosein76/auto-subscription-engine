"""Recursive, adaptive and bounded discovery of subscription sources."""
from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit

from ..ingestion import ingest_content
from .catalog import load_source_catalog
from .fetch import fetch_source
from .intelligence import SourceIntelligenceStore
from .models import (
    DiscoveryPolicy,
    DiscoveryResult,
    FetchOutcome,
    SourceDefinition,
    SourceOrigin,
    SourceReport,
)
from .ordering import order_sources
from .url import canonicalize_source_url, source_id_for_url, validate_source_url


class DiscoveryEngine:
    """Source graph crawler with learned ordering and persistent quarantine.

    Network I/O is concurrent but result processing is deterministic: each
    fetched batch is processed in scheduler order, never completion order.
    This keeps stats/subscription output reproducible while still avoiding a
    slow source serialising the whole discovery stage.
    """

    def __init__(
        self,
        seeds: list[SourceDefinition],
        *,
        policy: DiscoveryPolicy | None = None,
        state: SourceIntelligenceStore | None = None,
        state_path: Path | None = None,
        timeout: float = 15.0,
        retries: int = 2,
    ) -> None:
        self.seeds = [source for source in seeds if source.enabled]
        self.policy = policy or DiscoveryPolicy()
        self.state = state or SourceIntelligenceStore.load(state_path)
        self.state_path = state_path
        self.timeout = timeout
        self.retries = retries

    @classmethod
    def from_config(cls, config_path: Path, **kwargs) -> "DiscoveryEngine":
        return cls(load_source_catalog(config_path), **kwargs)

    def discover(self) -> DiscoveryResult:
        result = DiscoveryResult()
        queue: list[SourceDefinition] = order_sources(self.seeds, self.state)
        seen_urls: set[str] = set()
        seen_fingerprints: set[str] = set()
        discovered_sources: dict[str, SourceDefinition] = {}

        while queue and result.sources_total < self.policy.max_sources:
            batch: list[tuple[SourceDefinition, float]] = []
            concurrency = max(1, int(self.policy.fetch_concurrency))

            while (
                queue
                and len(batch) < concurrency
                and result.sources_total < self.policy.max_sources
            ):
                source = queue.pop(0)
                canonical_url = canonicalize_source_url(source.url)
                if canonical_url in seen_urls:
                    continue
                seen_urls.add(canonical_url)
                result.sources_total += 1
                stats = self.state.ensure(source)
                quality_before = stats.quality()

                if stats.is_quarantined():
                    result.sources_quarantined += 1
                    result.reports.append(
                        self._report(
                            source,
                            stats.host,
                            quality_before,
                            quality_before,
                            ok=False,
                            skipped_reason="quarantined",
                        )
                    )
                    continue
                batch.append((source, quality_before))

            if not batch:
                continue

            outcomes = self._fetch_batch([source for source, _quality in batch])
            result.sources_fetched += len(batch)
            newly_discovered: list[SourceDefinition] = []

            for source, quality_before in batch:
                stats = self.state.ensure(source)
                outcome = outcomes[source.source_id]
                if not outcome.ok or outcome.content is None:
                    result.sources_failed += 1
                    after = self.state.record_fetch(
                        source,
                        ok=False,
                        quarantine_after_failures=self.policy.quarantine_after_failures,
                        quarantine_base_minutes=self.policy.quarantine_base_minutes,
                        quarantine_max_hours=self.policy.quarantine_max_hours,
                    )
                    result.reports.append(
                        self._report(
                            source,
                            stats.host,
                            quality_before,
                            after.quality(),
                            ok=False,
                            status_code=outcome.status_code,
                            error=outcome.error,
                            byte_count=outcome.byte_count,
                        )
                    )
                    continue

                result.sources_success += 1
                ingestion = ingest_content(outcome.content, source=source.name)
                source_unique = 0
                for proxy in ingestion.proxies:
                    fingerprint = proxy.fingerprint
                    if not fingerprint:
                        continue
                    result.provenance.setdefault(fingerprint, set()).add(source.source_id)
                    if fingerprint in seen_fingerprints:
                        result.duplicates_removed += 1
                        continue
                    if len(result.proxies) >= self.policy.max_total_proxies:
                        break
                    seen_fingerprints.add(fingerprint)
                    result.proxies.append(proxy)
                    source_unique += 1

                nested = self._nested_sources(source, ingestion.nested_sources)
                after = self.state.record_fetch(
                    source,
                    ok=True,
                    byte_count=outcome.byte_count,
                    proxies_seen=len(ingestion.proxies),
                    unique_proxies=source_unique,
                    nested_sources=len(nested),
                    parse_issues=len(ingestion.issues),
                    quarantine_after_failures=self.policy.quarantine_after_failures,
                    quarantine_base_minutes=self.policy.quarantine_base_minutes,
                    quarantine_max_hours=self.policy.quarantine_max_hours,
                )
                result.reports.append(
                    self._report(
                        source,
                        stats.host,
                        quality_before,
                        after.quality(),
                        ok=True,
                        status_code=outcome.status_code,
                        byte_count=outcome.byte_count,
                        proxies_found=len(ingestion.proxies),
                        unique_proxies=source_unique,
                        nested_sources_found=len(nested),
                        issues=len(ingestion.issues),
                    )
                )

                if source.depth < self.policy.max_depth:
                    for item in nested:
                        canonical = canonicalize_source_url(item.url)
                        if canonical in seen_urls or item.source_id in discovered_sources:
                            continue
                        discovered_sources[item.source_id] = item
                        newly_discovered.append(item)

                if len(result.proxies) >= self.policy.max_total_proxies:
                    break

            if newly_discovered:
                queue.extend(newly_discovered)
                queue = order_sources(queue, self.state)

            if len(result.proxies) >= self.policy.max_total_proxies:
                break

        result.nested_sources = [
            discovered_sources[key] for key in sorted(discovered_sources)
        ]
        try:
            self.state.save(self.state_path)
        except OSError:
            # Discovery output remains usable even if optional telemetry cannot
            # be persisted. Live pipeline treats its own state persistence as
            # systemic because that is where adaptive verification feeds back.
            pass
        return result

    def _fetch_batch(self, sources: list[SourceDefinition]) -> dict[str, FetchOutcome]:
        workers = min(max(1, int(self.policy.fetch_concurrency)), len(sources))
        if workers <= 1:
            return {source.source_id: self._fetch_one_safe(source) for source in sources}
        outcomes: dict[str, FetchOutcome] = {}
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ase-source") as pool:
            future_map = {
                pool.submit(self._fetch_one_safe, source): source for source in sources
            }
            for future in as_completed(future_map):
                source = future_map[future]
                try:
                    outcomes[source.source_id] = future.result()
                except Exception as exc:  # belt-and-braces isolation
                    outcomes[source.source_id] = FetchOutcome(
                        source=source,
                        ok=False,
                        error=f"unexpected error: {type(exc).__name__}",
                    )
        return outcomes

    def _fetch_one_safe(self, source: SourceDefinition) -> FetchOutcome:
        try:
            return fetch_source(
                source,
                timeout=self.timeout,
                retries=self.retries,
            )
        except Exception as exc:
            return FetchOutcome(
                source=source,
                ok=False,
                error=f"unexpected error: {type(exc).__name__}",
            )

    @staticmethod
    def _report(
        source: SourceDefinition,
        host: str,
        quality_before: float,
        quality_after: float,
        *,
        ok: bool,
        status_code: int | None = None,
        error: str | None = None,
        byte_count: int = 0,
        proxies_found: int = 0,
        unique_proxies: int = 0,
        nested_sources_found: int = 0,
        issues: int = 0,
        skipped_reason: str | None = None,
    ) -> SourceReport:
        return SourceReport(
            source_id=source.source_id,
            name=source.name,
            host=host,
            depth=source.depth,
            origin=source.origin.value,
            ok=ok,
            status_code=status_code,
            error=error,
            byte_count=byte_count,
            proxies_found=proxies_found,
            unique_proxies=unique_proxies,
            nested_sources_found=nested_sources_found,
            issues=issues,
            quality_before=quality_before,
            quality_after=quality_after,
            skipped_reason=skipped_reason,
        )

    def _nested_sources(
        self,
        parent: SourceDefinition,
        urls: list[str],
    ) -> list[SourceDefinition]:
        output: list[SourceDefinition] = []
        seen: set[str] = set()
        for raw in urls:
            if len(output) >= self.policy.max_nested_per_source:
                break
            if not isinstance(raw, str):
                continue
            url = raw.strip()
            if validate_source_url(url) is not None:
                continue
            canonical = canonicalize_source_url(url)
            if canonical in seen:
                continue
            seen.add(canonical)
            source_id = source_id_for_url(canonical)
            host = (urlsplit(canonical).hostname or "source").lower()
            short = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]
            output.append(
                SourceDefinition(
                    name=f"nested:{host}:{short}",
                    url=canonical,
                    enabled=True,
                    priority=max(0, parent.priority - 10),
                    tags=("nested",),
                    origin=SourceOrigin.NESTED,
                    depth=parent.depth + 1,
                    parent_id=parent.source_id,
                    source_id=source_id,
                )
            )
        return output
