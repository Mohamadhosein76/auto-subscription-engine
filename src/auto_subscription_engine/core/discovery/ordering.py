"""Adaptive source ordering for discovery runs."""
from __future__ import annotations

from .intelligence import SourceIntelligenceStore
from .models import SourceDefinition


def source_priority(source: SourceDefinition, store: SourceIntelligenceStore) -> tuple[float, int, int, str]:
    """Deterministic priority: explicit priority + learned quality + shallower depth."""
    quality = store.quality(source.source_id)
    return (-float(source.priority) - quality * 100.0, source.depth, 0 if source.origin.value == "config" else 1, source.source_id)


def order_sources(sources: list[SourceDefinition], store: SourceIntelligenceStore) -> list[SourceDefinition]:
    return sorted(sources, key=lambda source: source_priority(source, store))
