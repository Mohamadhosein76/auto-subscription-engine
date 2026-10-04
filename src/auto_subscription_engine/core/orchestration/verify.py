"""Post-run output verification (used by the CLI ``verify`` command).

Checks that the generated artifacts exist, are internally consistent and
round-trip correctly — this is the "validate outputs" step of the GitHub
Actions workflow.
"""

from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime
from pathlib import Path

from ..models import SCHEME_ALIASES, SUPPORTED_PROTOCOLS

REQUIRED_STATS_KEYS = (
    "generated_at",
    "sources_total",
    "sources_success",
    "sources_failed",
    "configs_received",
    "configs_valid",
    "configs_invalid",
    "duplicates_removed",
    "final_configs",
    "count_by_protocol",
)


def verify_output_dir(output_dir: Path) -> list[str]:
    """Return a list of problems; an empty list means the outputs are valid."""
    problems: list[str] = []

    if not output_dir.is_dir():
        return [f"output directory not found: {output_dir}"]

    paths = {
        "subscription.txt": output_dir / "subscription.txt",
        "subscription_base64.txt": output_dir / "subscription_base64.txt",
        "stats.json": output_dir / "stats.json",
    }
    for name, path in paths.items():
        if not path.is_file():
            problems.append(f"missing file: {name}")
    if problems:
        return problems

    text = paths["subscription.txt"].read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip()]

    for line in lines:
        scheme = line.partition("://")[0].strip().lower()
        protocol = SCHEME_ALIASES.get(scheme, scheme)
        if protocol not in SUPPORTED_PROTOCOLS:
            problems.append(f"unsupported scheme in subscription.txt: {scheme or '(none)'}")

    encoded = paths["subscription_base64.txt"].read_text(encoding="ascii").strip()
    decoded: str | None = None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        problems.append("subscription_base64.txt is not valid base64")
    if decoded is not None and decoded != text:
        problems.append("base64 content does not match subscription.txt")

    try:
        stats = json.loads(paths["stats.json"].read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        problems.append("stats.json is not valid JSON")
        return problems

    if not isinstance(stats, dict):
        problems.append("stats.json must contain a JSON object")
        return problems

    for key in REQUIRED_STATS_KEYS:
        if key not in stats:
            problems.append(f"stats.json is missing key: {key}")

    try:
        datetime.fromisoformat(str(stats.get("generated_at", "")))
    except ValueError:
        problems.append("stats.json generated_at is not an ISO-8601 timestamp")

    final_configs = stats.get("final_configs")
    if isinstance(final_configs, int) and final_configs != len(lines):
        problems.append(
            f"stats.json final_configs ({final_configs}) != subscription lines ({len(lines)})"
        )

    count_by_protocol = stats.get("count_by_protocol")
    if isinstance(count_by_protocol, dict):
        total = sum(
            value for value in count_by_protocol.values() if isinstance(value, int)
        )
        if isinstance(final_configs, int) and total != final_configs:
            problems.append(
                f"sum of count_by_protocol ({total}) != final_configs ({final_configs})"
            )
        for protocol in count_by_protocol:
            if protocol not in SUPPORTED_PROTOCOLS:
                problems.append(f"count_by_protocol has unsupported protocol: {protocol}")
    else:
        problems.append("stats.json count_by_protocol must be a mapping")

    configs_valid = stats.get("configs_valid")
    # Discovery-stage duplicates are excluded from configs_valid upstream, so
    # the reconciling counter is the dedup-stage removals, not the combined
    # duplicates_removed total.
    duplicates_removed = stats.get("duplicates_removed_during_dedup")
    if (
        isinstance(configs_valid, int)
        and isinstance(duplicates_removed, int)
        and isinstance(final_configs, int)
        and configs_valid - duplicates_removed != final_configs
    ):
        problems.append(
            "stats.json inconsistency: configs_valid - duplicates_removed_during_dedup != final_configs"
        )

    sources_total = stats.get("sources_total")
    sources_success = stats.get("sources_success")
    sources_failed = stats.get("sources_failed")
    sources_skipped = stats.get("sources_skipped") or 0
    if (
        isinstance(sources_total, int)
        and isinstance(sources_success, int)
        and isinstance(sources_failed, int)
        and sources_total
        != sources_success + sources_failed + sources_skipped
    ):
        problems.append(
            "stats.json inconsistency: sources_total != sources_success + sources_failed + sources_skipped"
        )

    return problems
