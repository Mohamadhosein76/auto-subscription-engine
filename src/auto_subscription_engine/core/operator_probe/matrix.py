"""Read-only helpers for fresh per-operator evidence.

Stage 8 stores facts only. Stage 9 will consume these helpers when producing
operator-aware scores; Stage 10 will consume them when building per-operator
feeds.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def operator_record(
    state: dict[str, Any],
    fingerprint: str,
    operator_profile: str,
    *,
    stale_after_minutes: int,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    node = (state.get("nodes") or {}).get(fingerprint)
    if not isinstance(node, dict):
        return None
    record = (node.get("operators") or {}).get(operator_profile)
    if not isinstance(record, dict):
        return None
    observed = _parse_time(record.get("last_observed_at", ""))
    if observed is None:
        return None
    now = now or datetime.now(timezone.utc)
    result = dict(record)
    result["fresh"] = observed >= now - timedelta(minutes=max(1, int(stale_after_minutes)))
    return result


def node_operator_matrix(
    state: dict[str, Any],
    fingerprint: str,
    profiles: list[str] | tuple[str, ...],
    *,
    stale_after_minutes: int,
    now: datetime | None = None,
) -> dict[str, dict[str, Any] | None]:
    return {
        profile: operator_record(
            state,
            fingerprint,
            profile,
            stale_after_minutes=stale_after_minutes,
            now=now,
        )
        for profile in profiles
    }
