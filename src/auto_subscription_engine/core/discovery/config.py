"""Discovery policy configuration."""
from __future__ import annotations

from pathlib import Path

import yaml

from ..models import SourceConfigError
from .models import DiscoveryPolicy

_ALLOWED = frozenset(DiscoveryPolicy.__dataclass_fields__)


def load_discovery_policy(path: Path | None) -> DiscoveryPolicy:
    if path is None or not Path(path).is_file():
        return DiscoveryPolicy()
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise SourceConfigError(f"cannot read discovery config {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise SourceConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise SourceConfigError("discovery config must be a YAML mapping")
    section = raw.get("discovery", raw)
    if not isinstance(section, dict):
        raise SourceConfigError("discovery section must be a mapping")
    unknown = set(section) - _ALLOWED
    if unknown:
        raise SourceConfigError(f"unknown discovery settings: {sorted(unknown)}")
    values = {key: section[key] for key in _ALLOWED if key in section}
    for key, value in values.items():
        if not isinstance(value, int) or isinstance(value, bool):
            raise SourceConfigError(f"discovery.{key} must be an integer")
        if value < 0:
            raise SourceConfigError(f"discovery.{key} must be >= 0")
    policy = DiscoveryPolicy(**values)
    if policy.max_sources < 1:
        raise SourceConfigError("discovery.max_sources must be >= 1")
    if policy.max_total_proxies < 1:
        raise SourceConfigError("discovery.max_total_proxies must be >= 1")
    return policy
