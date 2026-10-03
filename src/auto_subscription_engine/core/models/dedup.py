"""Deduplication stage.

Duplicates are grouped by the logical fingerprint computed in the
normalize stage — never by raw URI text. Within a duplicate group the
surviving representative is chosen deterministically (prefer a config
with a display name, then the shorter URI, then lexicographic order) so
that the final output does not depend on source fetch order.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..models import ParsedConfig


def deduplicate(
    configs: Sequence[ParsedConfig],
) -> tuple[list[ParsedConfig], int]:
    """Remove duplicate configs; return (survivors, duplicates_removed)."""
    groups: dict[str, list[ParsedConfig]] = {}
    for config in configs:
        groups.setdefault(config.fingerprint, []).append(config)

    survivors: list[ParsedConfig] = []
    removed = 0
    for group in groups.values():
        removed += len(group) - 1
        survivors.append(_representative(group))
    return survivors, removed


def canonical_order(configs: Sequence[ParsedConfig]) -> list[ParsedConfig]:
    """Deterministic output ordering (protocol, host, port, name, URI)."""
    return sorted(
        configs,
        key=lambda c: (
            c.protocol,
            c.host or "",
            c.port or 0,
            c.name or "",
            c.original_uri,
        ),
    )


def _representative(group: Sequence[ParsedConfig]) -> ParsedConfig:
    def sort_key(config: ParsedConfig) -> tuple[int, int, str]:
        return (
            0 if config.name else 1,
            len(config.original_uri),
            config.original_uri,
        )

    return min(group, key=sort_key)
