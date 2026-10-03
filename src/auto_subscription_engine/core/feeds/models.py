"""Credential-bearing in-memory feed candidate model.

These objects are never serialized to metadata.  Only their URI artifacts are
written to subscription/feed files, while manifests contain safe IDs/counts.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from ..models import ParsedConfig


@dataclass(frozen=True)
class FeedCandidate:
    safe_id: str
    uri: str
    config: ParsedConfig
    metadata: dict[str, Any]

    @property
    def scores(self) -> dict[str, Any]:
        value = self.metadata.get("scores")
        return value if isinstance(value, dict) else {}

    def dimension(self, group: str, key: str | None = None) -> dict[str, Any]:
        value: Any = self.scores.get(group)
        if key is not None and isinstance(value, dict):
            value = value.get(key)
        return value if isinstance(value, dict) else {}
