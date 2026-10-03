from __future__ import annotations
from dataclasses import dataclass, field
from ..models import CanonicalProxy, OriginFormat

@dataclass(frozen=True)
class IngestionIssue:
    location: str
    reason: str

@dataclass
class IngestionResult:
    proxies: list[CanonicalProxy]=field(default_factory=list)
    nested_sources: list[str]=field(default_factory=list)
    issues: list[IngestionIssue]=field(default_factory=list)
    detected_format: OriginFormat=OriginFormat.UNKNOWN
