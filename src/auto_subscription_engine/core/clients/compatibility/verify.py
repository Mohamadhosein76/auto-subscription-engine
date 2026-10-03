"""Offline validation of Stage-7 compatibility evidence.

Stage 10 owns user-facing feed construction.  Stage 7 is validated here only
for its evidence contract: every security-publishable URI joins a live-node
record, compatible statuses are builder-realistic, and universal=true really
means all mapped cores passed.
"""
from __future__ import annotations
import json
from pathlib import Path
from ...models import ParseError, UnknownProtocolError
from ...models.fingerprint import normalize_config
from ...protocols import parse_uri
from ...security.policy import PUBLISHABLE_STATUSES
from ...utils.identity import config_safe_id
from ..builders.hiddify import build_hiddify_outbound
from ..builders.mihomo import build_mihomo_proxy
from ..builders.singbox import UnsupportedNodeError, build_outbound
from ..builders.xray import build_xray_outbound

_STATUS_FIELDS = {
    "singbox": "singbox_compatible",
    "xray": "xray_compatible",
    "hiddify": "hiddify_compatible",
    "mihomo": "mihomo_compatible",
}


def verify_compat_outputs(output_dir: Path) -> list[str]:
    root = Path(output_dir)
    problems: list[str] = []
    try:
        uris = [x.strip() for x in (root / "live_subscription.txt").read_text(encoding="utf-8").splitlines() if x.strip()]
        nodes = json.loads((root / "live_nodes.json").read_text(encoding="utf-8"))
        stats = json.loads((root / "live_stats.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [f"cannot read compatibility outputs: {exc}"]
    if not isinstance(nodes, list) or not isinstance(stats, dict):
        return ["compatibility outputs have invalid shape"]
    meta = {str(x.get("safe_id")): x for x in nodes if isinstance(x, dict) and x.get("safe_id")}
    seen: set[str] = set()
    for uri in uris:
        try:
            config = normalize_config(parse_uri(uri))
        except (ParseError, UnknownProtocolError, ValueError):
            problems.append("live_subscription.txt contains an unparseable URI")
            continue
        sid = config_safe_id(config)
        seen.add(sid)
        entry = meta.get(sid)
        if entry is None:
            problems.append(f"live subscription node {sid} missing from live_nodes.json")
            continue
        statuses = {core: entry.get(field) for core, field in _STATUS_FIELDS.items()}
        if statuses["xray"] == "pass":
            try: build_xray_outbound(config)
            except UnsupportedNodeError: problems.append(f"{sid} marked xray pass but builder refuses")
        if statuses["hiddify"] == "pass":
            try: build_hiddify_outbound(config)
            except UnsupportedNodeError: problems.append(f"{sid} marked hiddify pass but builder refuses")
        if statuses["singbox"] == "pass":
            try: build_outbound(config)
            except UnsupportedNodeError: problems.append(f"{sid} marked singbox pass but builder refuses")
        if statuses["mihomo"] == "pass":
            try: build_mihomo_proxy(config)
            except UnsupportedNodeError: problems.append(f"{sid} marked mihomo pass but builder refuses")
        expected_universal = all(value == "pass" for value in statuses.values())
        if bool(entry.get("universal_compatible")) != expected_universal:
            problems.append(f"{sid} universal_compatible disagrees with per-core evidence")
    # Security-blocked/quarantined nodes and ASN-diversity exclusions are
    # deliberately withheld from the live subscription; only publishable,
    # non-excluded nodes are required to appear in it.
    required = {
        sid
        for sid, entry in meta.items()
        if entry.get("security_status") in PUBLISHABLE_STATUSES
        and not entry.get("asn_diversity_excluded")
    }
    missing = sorted(required - seen)
    if missing:
        problems.append(
            f"live_nodes.json contains {len(missing)} publishable nodes missing from live subscription"
        )
    compat = stats.get("compatibility")
    if not isinstance(compat, dict):
        problems.append("live_stats.json missing compatibility block")
    return problems
