"""File-oriented Stage-9 scorecard enrichment."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ..utils.identity import safe_id
from ..operator_probe import load_operator_probe_config, node_operator_matrix
from ..scheduling import ReliabilityHistory
from .engine import score_node_card
from .policy import ScoringPolicy


@dataclass(frozen=True)
class ScoringOptions:
    output_dir: Path
    testing_config_path: Path = Path("config/testing.yaml")
    history_path: Path = Path("data/history.json")
    operator_state_path: Path = Path("data/operator_probes.json")
    operator_config_path: Path = Path("config/operator_probes.yaml")
    now: datetime | None = None


def run_scoring_stage(options: ScoringOptions) -> dict[str, Any]:
    output_dir = Path(options.output_dir)
    nodes_path = output_dir / "live_nodes.json"
    stats_path = output_dir / "live_stats.json"
    nodes = json.loads(nodes_path.read_text(encoding="utf-8"))
    stats = json.loads(stats_path.read_text(encoding="utf-8"))
    if not isinstance(nodes, list) or not isinstance(stats, dict):
        raise ValueError("scoring inputs have invalid shape")
    scoring_cfg = _load_scoring_mapping(options.testing_config_path)
    policy = ScoringPolicy.from_mapping(scoring_cfg)
    history = ReliabilityHistory.load(options.history_path)
    history_by_safe = {safe_id(fp): entry for fp, entry in history.entries.items()}
    fp_by_safe = {safe_id(fp): fp for fp in history.entries}
    operator_state = _load_json(options.operator_state_path, {"nodes": {}})
    # Include operator-only fingerprints that may have aged out of local history.
    for fp in (operator_state.get("nodes") or {}):
        fp_by_safe.setdefault(safe_id(str(fp)), str(fp))
    operator_cfg = load_operator_probe_config(options.operator_config_path)
    profiles = [key for key, profile in operator_cfg.profiles.items() if profile.enabled]
    labels = {
        key: {"display_name": profile.display_name, "network_type": profile.network_type}
        for key, profile in operator_cfg.profiles.items() if profile.enabled
    }
    now = options.now or datetime.now(timezone.utc)

    cards: dict[str, Any] = {}
    global_scores: list[int] = []
    operator_known: dict[str, int] = {key: 0 for key in profiles}
    operator_fresh: dict[str, int] = {key: 0 for key in profiles}
    client_scored: dict[str, int] = {}

    for entry in nodes:
        if not isinstance(entry, dict):
            continue
        sid = str(entry.get("safe_id") or "")
        if not sid:
            continue
        fingerprint = fp_by_safe.get(sid)
        history_entry = history_by_safe.get(sid)
        matrix = node_operator_matrix(
            operator_state, fingerprint, profiles,
            stale_after_minutes=operator_cfg.policy.stale_after_minutes, now=now,
        ) if fingerprint else {key: None for key in profiles}
        card = score_node_card(
            entry, history_entry=history_entry, operator_records=matrix,
            operator_labels=labels, policy=policy, now=now,
        )
        payload = card.to_dict()
        entry["score"] = card.global_score
        entry["scores"] = payload
        cards[sid] = payload
        global_scores.append(card.global_score)
        for key, dim in card.operators.items():
            if dim.score is not None:
                operator_known[key] = operator_known.get(key, 0) + 1
                if dim.fresh:
                    operator_fresh[key] = operator_fresh.get(key, 0) + 1
        for key, dim in card.clients.items():
            if dim.score is not None:
                client_scored[key] = client_scored.get(key, 0) + 1

    nodes_path.write_text(json.dumps(nodes, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "scorecards.json").write_text(
        json.dumps(cards, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    scoring_stats = {
        "schema_version": 1,
        "scored_nodes": len(cards),
        "global_score_min": min(global_scores) if global_scores else None,
        "global_score_max": max(global_scores) if global_scores else None,
        "global_score_median": _median_int(global_scores),
        "operator_evidence_nodes": dict(sorted(operator_known.items())),
        "operator_fresh_nodes": dict(sorted(operator_fresh.items())),
        "client_scored_nodes": dict(sorted(client_scored.items())),
        "operator_stale_after_minutes": operator_cfg.policy.stale_after_minutes,
    }
    stats["scoring_v2"] = scoring_stats
    stats_path.write_text(json.dumps(stats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return scoring_stats


def verify_scoring_outputs(output_dir: Path) -> list[str]:
    output_dir = Path(output_dir)
    problems: list[str] = []
    try:
        nodes = json.loads((output_dir / "live_nodes.json").read_text(encoding="utf-8"))
        cards = json.loads((output_dir / "scorecards.json").read_text(encoding="utf-8"))
        stats = json.loads((output_dir / "live_stats.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [f"cannot read scoring outputs: {exc}"]
    if not isinstance(nodes, list) or not isinstance(cards, dict):
        return ["scoring outputs have invalid JSON shape"]
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            problems.append(f"live_nodes entry {index} is not an object")
            continue
        sid = str(node.get("safe_id") or "")
        score_payload = node.get("scores")
        if not sid or not isinstance(score_payload, dict):
            problems.append(f"live_nodes entry {index} missing Stage-9 scores")
            continue
        if cards.get(sid) != score_payload:
            problems.append(f"scorecards.json mismatch for {sid}")
        _verify_score_payload(score_payload, f"node {sid}", problems)
        global_score = ((score_payload.get("global") or {}).get("score"))
        if node.get("score") != global_score:
            problems.append(f"node {sid} score does not equal scores.global.score")
        if _contains_sensitive_payload(score_payload):
            problems.append(f"node {sid} score payload leaks sensitive data")
    scoring_stats = stats.get("scoring_v2") if isinstance(stats, dict) else None
    if not isinstance(scoring_stats, dict):
        problems.append("live_stats.json missing scoring_v2 block")
    elif int(scoring_stats.get("scored_nodes", -1)) != len(cards):
        problems.append("scoring_v2.scored_nodes does not match scorecards.json")
    return problems


def _verify_score_payload(payload: dict[str, Any], label: str, problems: list[str]) -> None:
    for key in ("global", "connectivity", "latency", "reliability", "freshness", "security"):
        item = payload.get(key)
        if not isinstance(item, dict):
            problems.append(f"{label} missing score dimension {key}")
            continue
        score = item.get("score")
        if score is not None and (not isinstance(score, int) or not 0 <= score <= 100):
            problems.append(f"{label} has invalid {key}.score")
        confidence = item.get("confidence")
        if not isinstance(confidence, int) or not 0 <= confidence <= 100:
            problems.append(f"{label} has invalid {key}.confidence")
    for group in ("operators", "clients"):
        values = payload.get(group)
        if not isinstance(values, dict):
            problems.append(f"{label} missing score group {group}")
            continue
        for name, item in values.items():
            if not isinstance(item, dict):
                problems.append(f"{label} {group}.{name} is not an object")
                continue
            score = item.get("score")
            if score is not None and (not isinstance(score, int) or not 0 <= score <= 100):
                problems.append(f"{label} has invalid {group}.{name}.score")


def _contains_sensitive_payload(value: Any) -> bool:
    sensitive = {"uri", "original_uri", "password", "uuid", "token", "secret", "identity"}
    if isinstance(value, dict):
        return any(str(key).lower() in sensitive or _contains_sensitive_payload(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_sensitive_payload(item) for item in value)
    return isinstance(value, str) and "://" in value


def _load_scoring_mapping(path: Path) -> dict[str, Any]:
    if not Path(path).is_file():
        return {}
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("testing config must be a mapping")
    scoring = raw.get("scoring") or {}
    if not isinstance(scoring, dict):
        raise ValueError("testing config scoring section must be a mapping")
    return scoring


def _load_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not Path(path).is_file():
        return dict(default)
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return dict(default)
    return raw if isinstance(raw, dict) else dict(default)


def _median_int(values: list[int]) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return int(round((ordered[middle - 1] + ordered[middle]) / 2.0))
