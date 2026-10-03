"""Stage-10 score-aware feed construction.

The compatibility stage only supplies evidence.  This module is the single
source of truth for deciding which verified node enters which user-facing feed.
"""
from __future__ import annotations

import base64
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from ..utils.identity import config_safe_id
from ..clients.exporters.native import write_client_manifest, write_mihomo_configs, write_singbox_configs
from ..clients.registry import CLIENTS
from ..models import ParseError, UnknownProtocolError
from ..models.fingerprint import normalize_config
from ..protocols import parse_uri
from .models import FeedCandidate
from .policy import FeedPolicy, load_feed_policy


@dataclass(frozen=True)
class FeedOptions:
    output_dir: Path
    config_path: Path = Path("config/feeds.yaml")


_CLIENT_STATUS_FIELD = {
    "v2rayng": "xray_compatible",
    "hiddify": "hiddify_compatible",
    "nekobox": "singbox_compatible",
    "singbox": "singbox_compatible",
    "mihomo": "mihomo_compatible",
}


def run_feed_stage(options: FeedOptions) -> dict[str, Any]:
    output_dir = Path(options.output_dir)
    policy = load_feed_policy(options.config_path)
    candidates = _load_candidates(output_dir)
    stats = _load_json(output_dir / "live_stats.json", {})

    clients_dir = output_dir / "clients"
    networks_dir = output_dir / "networks"
    profiles_dir = output_dir / "profiles"
    operators_dir = output_dir / "operators"
    for directory in (clients_dir, networks_dir, profiles_dir, operators_dir):
        _reset_dir(directory)

    feed_counts: dict[str, int] = {}

    universal = _select(
        [c for c in candidates if bool(c.metadata.get("universal_compatible"))],
        policy,
        score_kind="global",
    )
    _write_uri_feed(clients_dir / "universal.txt", universal)
    feed_counts["clients/universal"] = len(universal)

    client_sets: dict[str, list[FeedCandidate]] = {}
    for client, spec in CLIENTS.items():
        field = _CLIENT_STATUS_FIELD[client]
        eligible = [
            c for c in candidates
            if c.metadata.get(field) == "pass" and _client_score(c, client) is not None
        ]
        passing = [c for c in eligible if int(_client_score(c, client) or 0) >= policy.min_client_score]
        selected = _with_fallback(passing, eligible, policy, score_kind="client", score_key=client)
        client_sets[client] = selected
        if spec.format == "uri":
            _write_uri_feed(clients_dir / spec.artifact, selected)
        elif spec.format == "mihomo-yaml":
            write_mihomo_configs(clients_dir / spec.artifact, [c.config for c in selected])
        elif spec.format == "singbox-json":
            write_singbox_configs(clients_dir / spec.artifact, [c.config for c in selected])
        feed_counts[f"clients/{client}"] = len(selected)

    recommended_pool = [c for c in universal if _score(c, "global") >= policy.recommended_min_global]
    recommended = _with_fallback(recommended_pool, universal, policy, score_kind="global")
    secure_pool = [
        c for c in candidates
        if _score(c, "global") >= policy.secure_min_global
        and _score(c, "security") >= policy.secure_min_security
    ]
    secure = _select(secure_pool, policy, score_kind="global")
    max_compat = _select(candidates, policy, score_kind="global")
    _write_uri_feed(profiles_dir / "recommended.txt", recommended)
    _write_uri_feed(profiles_dir / "secure.txt", secure)
    _write_uri_feed(profiles_dir / "max-compat.txt", max_compat)
    feed_counts["profiles/recommended"] = len(recommended)
    feed_counts["profiles/secure"] = len(secure)
    feed_counts["profiles/max-compat"] = len(max_compat)

    network_predicates = {
        "direct-ip": lambda c: bool((c.metadata.get("network_profile") or {}).get("direct_ip")),
        "ipv4": lambda c: bool((c.metadata.get("network_profile") or {}).get("ipv4")),
        "ipv6": lambda c: bool((c.metadata.get("network_profile") or {}).get("ipv6")),
        "tcp": lambda c: bool((c.metadata.get("network_profile") or {}).get("tcp")),
        "udp": lambda c: bool((c.metadata.get("network_profile") or {}).get("udp")),
        "port443": lambda c: bool((c.metadata.get("network_profile") or {}).get("port_443")),
        "mobile-safe": lambda c: _mobile_safe(c),
    }
    for name, predicate in network_predicates.items():
        selected = _select([c for c in candidates if predicate(c)], policy, score_kind="global")
        _write_uri_feed(networks_dir / f"{name}.txt", selected)
        feed_counts[f"networks/{name}"] = len(selected)

    operator_summary: dict[str, Any] = {}
    operator_names = sorted({
        key for c in candidates for key in ((c.scores.get("operators") or {}).keys())
    })
    for operator in operator_names:
        op_dir = operators_dir / operator
        op_dir.mkdir(parents=True, exist_ok=True)
        op_eligible = [c for c in candidates if _operator_eligible(c, operator, policy)]
        op_ranked = _select(op_eligible, policy, score_kind="operator", score_key=operator)
        client_counts: dict[str, int] = {}
        for client, spec in CLIENTS.items():
            selected = [
                c for c in op_ranked
                if c.metadata.get(_CLIENT_STATUS_FIELD[client]) == "pass"
                and (_client_score(c, client) or 0) >= policy.min_client_score
            ]
            selected = _select(selected, policy, score_kind="operator", score_key=operator)
            client_counts[client] = len(selected)
            if not selected:
                continue
            if spec.format == "uri":
                _write_uri_feed(op_dir / spec.artifact, selected)
            elif spec.format == "mihomo-yaml":
                write_mihomo_configs(op_dir / spec.artifact, [c.config for c in selected])
            elif spec.format == "singbox-json":
                write_singbox_configs(op_dir / spec.artifact, [c.config for c in selected])
        op_universal = [c for c in op_ranked if bool(c.metadata.get("universal_compatible"))]
        if op_universal:
            _write_uri_feed(op_dir / "universal.txt", op_universal)
        manifest = {
            "schema_version": 1,
            "operator": operator,
            "fresh_evidence_nodes": len(op_ranked),
            "universal_nodes": len(op_universal),
            "client_counts": dict(sorted(client_counts.items())),
            "policy": {
                "min_operator_score": policy.min_operator_score,
                "min_operator_confidence": policy.min_operator_confidence,
                "require_fresh": policy.require_fresh_operator_evidence,
            },
        }
        (op_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        operator_summary[operator] = manifest

    core_statuses = ((stats.get("compatibility") or {}).get("cores_available") or {})
    write_client_manifest(
        clients_dir / "manifest.json",
        feed_counts={key.split("/", 1)[1]: value for key, value in feed_counts.items() if key.startswith("clients/")},
        core_statuses={k: ("available" if v else "unavailable") for k, v in core_statuses.items()},
    )

    # Legacy main URL stays universal for backwards compatibility; ordering is now score-aware.
    _write_main_subscription(output_dir, universal)

    manifest = {
        "schema_version": 1,
        "engine": "score-aware-feed-v2",
        "legacy_main_policy": "universal-score-ranked",
        "feed_counts": dict(sorted(feed_counts.items())),
        "operators": operator_summary,
        "thresholds": {
            "min_client_score": policy.min_client_score,
            "min_operator_score": policy.min_operator_score,
            "min_operator_confidence": policy.min_operator_confidence,
            "recommended_min_global": policy.recommended_min_global,
            "secure_min_security": policy.secure_min_security,
        },
    }
    (output_dir / "feed_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    stats["universal_count"] = len(universal)
    stats["mobile_safe_count"] = feed_counts.get("networks/mobile-safe", 0)
    stats["feed_engine_v2"] = {
        "candidate_nodes": len(candidates),
        "feed_counts": dict(sorted(feed_counts.items())),
        "operator_fresh_counts": {k: int(v["fresh_evidence_nodes"]) for k, v in operator_summary.items()},
    }
    (output_dir / "live_stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest


def _load_candidates(output_dir: Path) -> list[FeedCandidate]:
    nodes = _load_json(output_dir / "live_nodes.json", [])
    if not isinstance(nodes, list):
        raise ValueError("live_nodes.json must be an array")
    meta = {str(x.get("safe_id")): x for x in nodes if isinstance(x, dict) and x.get("safe_id")}
    lines = [x.strip() for x in (output_dir / "live_subscription.txt").read_text(encoding="utf-8").splitlines() if x.strip()]
    candidates: list[FeedCandidate] = []
    seen: set[str] = set()
    for uri in lines:
        try:
            config = normalize_config(parse_uri(uri))
        except (ParseError, UnknownProtocolError, ValueError):
            continue
        sid = config_safe_id(config)
        if sid in seen or sid not in meta:
            continue
        seen.add(sid)
        candidates.append(FeedCandidate(sid, uri, config, meta[sid]))
    return candidates


def _score(candidate: FeedCandidate, kind: str, key: str | None = None) -> int:
    dim = candidate.dimension(kind, key)
    value = dim.get("score")
    return int(value) if isinstance(value, int) else 0


def _client_score(candidate: FeedCandidate, client: str) -> int | None:
    value = candidate.dimension("clients", client).get("score")
    return int(value) if isinstance(value, int) else None


def _operator_eligible(candidate: FeedCandidate, operator: str, policy: FeedPolicy) -> bool:
    dim = candidate.dimension("operators", operator)
    score = dim.get("score")
    confidence = dim.get("confidence")
    if not isinstance(score, int) or score < policy.min_operator_score:
        return False
    if not isinstance(confidence, int) or confidence < policy.min_operator_confidence:
        return False
    if policy.require_fresh_operator_evidence and dim.get("fresh") is not True:
        return False
    return True


def _sort_key(candidate: FeedCandidate, kind: str, key: str | None = None) -> tuple:
    primary = _score(candidate, kind, key)
    global_score = _score(candidate, "global")
    reliability = _score(candidate, "reliability")
    latency = _score(candidate, "latency")
    return (-primary, -global_score, -reliability, -latency, candidate.safe_id)


def _select(candidates: Iterable[FeedCandidate], policy: FeedPolicy, *, score_kind: str, score_key: str | None = None) -> list[FeedCandidate]:
    ordered = sorted(candidates, key=lambda c: _sort_key(c, score_kind, score_key))
    selected: list[FeedCandidate] = []
    asn_counts: Counter[str] = Counter()
    prefix_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    source_soft = max(1, int(policy.max_nodes_per_feed * policy.per_source_soft_limit))
    deferred: list[FeedCandidate] = []
    for candidate in ordered:
        asn = str(candidate.metadata.get("asn") or "")
        prefix = str(candidate.metadata.get("prefix") or "")
        source = str(candidate.metadata.get("source") or "")
        if asn and asn_counts[asn] >= policy.per_asn_limit:
            deferred.append(candidate); continue
        if prefix and prefix_counts[prefix] >= policy.per_prefix_limit:
            deferred.append(candidate); continue
        if source and source_counts[source] >= source_soft:
            deferred.append(candidate); continue
        selected.append(candidate)
        if asn: asn_counts[asn] += 1
        if prefix: prefix_counts[prefix] += 1
        if source: source_counts[source] += 1
        if len(selected) >= policy.max_nodes_per_feed:
            break
    if len(selected) < min(policy.min_fallback_nodes, policy.max_nodes_per_feed):
        chosen = {c.safe_id for c in selected}
        for candidate in deferred:
            if candidate.safe_id in chosen:
                continue
            selected.append(candidate); chosen.add(candidate.safe_id)
            if len(selected) >= min(policy.min_fallback_nodes, policy.max_nodes_per_feed):
                break
    return selected


def _with_fallback(primary: list[FeedCandidate], fallback: list[FeedCandidate], policy: FeedPolicy, *, score_kind: str, score_key: str | None = None) -> list[FeedCandidate]:
    selected = _select(primary, policy, score_kind=score_kind, score_key=score_key)
    if len(selected) >= min(policy.min_fallback_nodes, len(fallback)):
        return selected
    return _select(fallback, policy, score_kind=score_kind, score_key=score_key)


def _mobile_safe(candidate: FeedCandidate) -> bool:
    profile = candidate.metadata.get("network_profile") or {}
    if not isinstance(profile, dict):
        return False
    if not (profile.get("ipv4") or profile.get("ipv6")):
        return False
    if candidate.metadata.get("proxy_latency_ms") is not None and float(candidate.metadata["proxy_latency_ms"]) > 1500:
        return False
    return not bool(profile.get("udp_dependency"))


def _write_uri_feed(path: Path, candidates: list[FeedCandidate]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(c.uri for c in candidates) + ("\n" if candidates else "")
    path.write_text(body, encoding="utf-8")
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    path.with_name(path.stem + "_base64.txt").write_text(encoded + "\n", encoding="ascii")


def _write_main_subscription(output_dir: Path, candidates: list[FeedCandidate]) -> None:
    body = "\n".join(c.uri for c in candidates) + ("\n" if candidates else "")
    (output_dir / "live_subscription.txt").write_text(body, encoding="utf-8")
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    (output_dir / "live_subscription_base64.txt").write_text(encoded + "\n", encoding="ascii")


def _write_best(output_dir: Path, candidates: list[FeedCandidate]) -> None:
    body = "\n".join(c.uri for c in candidates) + ("\n" if candidates else "")
    (output_dir / "best.txt").write_text(body, encoding="utf-8")


def _write_countries(output_dir: Path, candidates: list[FeedCandidate]) -> None:
    root = output_dir / "countries"
    _reset_dir(root)
    groups: dict[str, list[FeedCandidate]] = defaultdict(list)
    for candidate in candidates:
        code = str(candidate.metadata.get("country_code") or "XX").upper()
        groups[code].append(candidate)
    for code, rows in sorted(groups.items()):
        body = "\n".join(c.uri for c in rows) + "\n"
        (root / f"{code}.txt").write_text(body, encoding="utf-8")


def _reset_dir(path: Path) -> None:
    import shutil
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _load_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return default
