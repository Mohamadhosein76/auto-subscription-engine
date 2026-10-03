"""Feed selection policy for Stage 10."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import yaml


@dataclass(frozen=True)
class FeedPolicy:
    max_nodes_per_feed: int = 200
    min_client_score: int = 50
    min_operator_score: int = 65
    min_operator_confidence: int = 50
    require_fresh_operator_evidence: bool = True
    recommended_min_global: int = 60
    secure_min_global: int = 50
    secure_min_security: int = 80
    min_fallback_nodes: int = 3
    per_asn_limit: int = 8
    per_prefix_limit: int = 4
    per_source_soft_limit: float = 0.50

    @classmethod
    def from_mapping(cls, raw: dict[str, Any] | None) -> "FeedPolicy":
        raw = raw or {}
        policy = cls(
            max_nodes_per_feed=int(raw.get("max_nodes_per_feed", 200)),
            min_client_score=int(raw.get("min_client_score", 50)),
            min_operator_score=int(raw.get("min_operator_score", 65)),
            min_operator_confidence=int(raw.get("min_operator_confidence", 50)),
            require_fresh_operator_evidence=bool(raw.get("require_fresh_operator_evidence", True)),
            recommended_min_global=int(raw.get("recommended_min_global", 60)),
            secure_min_global=int(raw.get("secure_min_global", 50)),
            secure_min_security=int(raw.get("secure_min_security", 80)),
            min_fallback_nodes=int(raw.get("min_fallback_nodes", 3)),
            per_asn_limit=int(raw.get("per_asn_limit", 8)),
            per_prefix_limit=int(raw.get("per_prefix_limit", 4)),
            per_source_soft_limit=float(raw.get("per_source_soft_limit", 0.50)),
        )
        policy.validate()
        return policy

    def validate(self) -> None:
        for name in (
            "min_client_score", "min_operator_score", "min_operator_confidence",
            "recommended_min_global", "secure_min_global", "secure_min_security",
        ):
            value = getattr(self, name)
            if not 0 <= value <= 100:
                raise ValueError(f"{name} must be between 0 and 100")
        if self.max_nodes_per_feed <= 0:
            raise ValueError("max_nodes_per_feed must be > 0")
        if self.min_fallback_nodes < 0:
            raise ValueError("min_fallback_nodes must be >= 0")
        if self.per_asn_limit <= 0 or self.per_prefix_limit <= 0:
            raise ValueError("diversity limits must be > 0")
        if not 0 < self.per_source_soft_limit <= 1:
            raise ValueError("per_source_soft_limit must be in (0, 1]")


def load_feed_policy(path: Path) -> FeedPolicy:
    if not Path(path).is_file():
        return FeedPolicy()
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("feeds config must be a mapping")
    section = raw.get("feeds", raw)
    if not isinstance(section, dict):
        raise ValueError("feeds config section must be a mapping")
    return FeedPolicy.from_mapping(section)
