"""Load validated seed sources into the central discovery model."""
from __future__ import annotations

from pathlib import Path

import yaml

from ..models import SourceConfigError
from .models import SourceDefinition, SourceOrigin
from .url import source_id_for_url, validate_source_url

_ALLOWED_KEYS = frozenset({"name", "url", "enabled", "priority", "tags"})


def load_source_catalog(path: Path) -> list[SourceDefinition]:
    if not path.is_file():
        raise SourceConfigError(f"sources config not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SourceConfigError(f"cannot read sources config {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise SourceConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
        raise SourceConfigError("sources config must be a mapping with a 'sources' list")
    if not data["sources"]:
        raise SourceConfigError("no sources defined in config")

    sources: list[SourceDefinition] = []
    seen_names: set[str] = set()
    seen_ids: set[str] = set()
    for index, entry in enumerate(data["sources"]):
        if not isinstance(entry, dict):
            raise SourceConfigError(f"source #{index} must be a mapping with 'name' and 'url'")
        unknown = set(entry) - _ALLOWED_KEYS
        if unknown:
            raise SourceConfigError(f"source #{index} has unknown keys: {sorted(unknown)}")
        name = entry.get("name")
        url = entry.get("url")
        if not isinstance(name, str) or not name.strip():
            raise SourceConfigError(f"source #{index} needs a non-empty 'name'")
        if not isinstance(url, str) or not url.strip():
            raise SourceConfigError(f"source #{index} needs a non-empty 'url'")
        name = name.strip()
        url = url.strip()
        problem = validate_source_url(url)
        if problem is not None:
            raise SourceConfigError(f"source '{name}' has an invalid url: {problem}")
        if name in seen_names:
            raise SourceConfigError(f"duplicate source name: '{name}'")
        source_id = source_id_for_url(url)
        if source_id in seen_ids:
            raise SourceConfigError(f"duplicate source URL: '{name}'")
        enabled = entry.get("enabled", True)
        if not isinstance(enabled, bool):
            raise SourceConfigError(f"source '{name}' enabled must be boolean")
        priority = entry.get("priority", 50)
        if not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= 100:
            raise SourceConfigError(f"source '{name}' priority must be an integer from 0 to 100")
        tags_raw = entry.get("tags", [])
        if not isinstance(tags_raw, list) or any(not isinstance(tag, str) for tag in tags_raw):
            raise SourceConfigError(f"source '{name}' tags must be a list of strings")
        sources.append(SourceDefinition(
            name=name,
            url=url,
            enabled=enabled,
            priority=priority,
            tags=tuple(dict.fromkeys(tag.strip() for tag in tags_raw if tag.strip())),
            origin=SourceOrigin.CONFIG,
            depth=0,
            source_id=source_id,
        ))
        seen_names.add(name)
        seen_ids.add(source_id)
    return sources
