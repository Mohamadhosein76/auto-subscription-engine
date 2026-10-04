"""Local worker executed by the Go operator probe agent.

The Go agent authenticates the job envelope and signs the result. This worker
only consumes an already-decoded job payload and reuses the central Python
verification/core-runtime implementation so protocol logic is never duplicated.
"""
from __future__ import annotations

import argparse
import json
import platform
import secrets
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ..clients.install import verified_core_paths
from ..network import is_ip_literal
from ..protocols.registry import parse_uri
from ..models.fingerprint import normalize_config
from ..verification.engine import VerificationEngine
from ..verification.policy import VerificationPolicy
from .models import ProbeNodeResult, ProbeResultBatch

AGENT_WORKER_VERSION = "stage8-1"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_job(path: Path) -> dict:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or int(raw.get("schema_version", 0)) != 1:
        raise ValueError("unsupported probe job")
    expires = datetime.fromisoformat(str(raw["expires_at"]).replace("Z", "+00:00"))
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires.astimezone(timezone.utc) < datetime.now(timezone.utc):
        raise ValueError("probe job expired")
    return raw


def execute_job(job: dict, *, core_dir: Path, testing_config: Path, probe_id: str, operator_profile: str) -> dict:
    if str(job.get("operator_profile")) != operator_profile:
        raise ValueError("job operator profile mismatch")
    testing_cfg = yaml.safe_load(Path(testing_config).read_text(encoding="utf-8")) or {}
    policy = VerificationPolicy.from_mapping(testing_cfg.get("verification") or {})
    core_paths = verified_core_paths(Path(core_dir), testing_cfg)
    if not core_paths:
        raise RuntimeError("no checksum-verified core binaries available")

    configs = []
    by_fingerprint: dict[str, dict] = {}
    for item in job.get("candidates") or []:
        if not isinstance(item, dict):
            continue
        config = normalize_config(parse_uri(str(item.get("uri", ""))))
        if config.fingerprint != str(item.get("fingerprint", "")):
            raise ValueError("candidate fingerprint mismatch")
        configs.append(config)
        by_fingerprint[config.fingerprint] = item

    started = _iso_now()
    engine = VerificationEngine(core_paths, policy)
    preflight = engine.preflight(configs)
    eligible = [item for item in preflight if item.preflight_success]
    runtime_results, _not_tested = engine.runtime(eligible)
    runtime_map = {item.fingerprint: item for item in runtime_results}
    preflight_map = {item.fingerprint: item for item in preflight}

    results: list[ProbeNodeResult] = []
    for config in configs:
        pf = preflight_map.get(config.fingerprint)
        rt = runtime_map.get(config.fingerprint)
        source = by_fingerprint[config.fingerprint]
        results.append(
            ProbeNodeResult(
                safe_id=str(source.get("safe_id", "")),
                fingerprint=config.fingerprint,
                protocol=config.protocol,
                direct_ip=bool(source.get("direct_ip", is_ip_literal(config.host or ""))),
                passed=bool(rt and rt.passed),
                runtime_core=rt.runtime_core if rt else None,
                attempted_cores=tuple(rt.attempted_cores) if rt else (),
                success_count=int(rt.success_count) if rt else 0,
                success_ratio=float(rt.success_ratio) if rt else 0.0,
                round_success_ratios=tuple(rt.round_success_ratios) if rt else (),
                latency_p50_ms=rt.proxy_latency_ms if rt else None,
                latency_p95_ms=rt.latency_p95_ms if rt else None,
                jitter_ms=rt.jitter_ms if rt else None,
                preflight_success=bool(pf and pf.preflight_success),
                ipv4_success=bool(pf and pf.ipv4_success),
                ipv6_success=bool(pf and pf.ipv6_success),
                failure_reason=(rt.failure_reason if rt else (pf.failure_reason if pf else "not_tested")),
            )
        )

    batch = ProbeResultBatch(
        schema_version=1,
        result_id=secrets.token_hex(16),
        job_id=str(job["job_id"]),
        operator_profile=operator_profile,
        probe_id=probe_id,
        started_at=started,
        completed_at=_iso_now(),
        agent_version=AGENT_WORKER_VERSION,
        network={"os": platform.system().lower(), "arch": platform.machine().lower()},
        results=tuple(results),
    )
    return batch.to_dict()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ase-operator-probe-worker")
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--core-dir", type=Path, required=True)
    parser.add_argument("--testing-config", type=Path, required=True)
    parser.add_argument("--probe-id", required=True)
    parser.add_argument("--operator-profile", required=True)
    args = parser.parse_args(argv)
    payload = execute_job(
        _load_job(args.job),
        core_dir=args.core_dir,
        testing_config=args.testing_config,
        probe_id=args.probe_id,
        operator_profile=args.operator_profile,
    )
    args.output.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
