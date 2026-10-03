"""Command-line interface.

Task 1 commands: ``run`` (default) and ``verify``.
Task 2 commands: ``live`` (real connectivity pipeline), ``core-install"
(pinned proxy core) and ``verify-live`` (live output validation).
Task 3 commands: ``publish`` (guarded, transactional publish to public/)
and ``verify-publish`` (public tree validation).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from .core.orchestration.live import (
    LiveOptions,
    SystemicPipelineError,
    load_testing_config,
    run_live_pipeline,
    verify_live_outputs,
)
from .core.models import SourceConfigError
from .core.orchestration.pipeline import RunOptions, run_pipeline, summarize
from .core.hardening.publication import (
    PublishError,
    PublishOptions,
    resolve_history_baseline,
    run_publish,
    verify_public_dir,
)
from .core.hardening.release import run_release_gate, write_release_gate_report
from .core.operator_probe.config import load_operator_probe_config
from .core.operator_probe.jobs import build_probe_job, read_candidate_uris, write_signed_probe_job
from .core.operator_probe.store import OperatorProbeStore

from .core.scoring import ScoringOptions, run_scoring_stage, verify_scoring_outputs
from .core.feeds import FeedOptions, run_feed_stage, verify_feed_outputs

from .core.clients.install import (
    CoreInstallError,
    install_core_binary,
    specs_from_testing_config,
    verified_core_paths,
)
from .core.security.engine import (
    SecurityOptions,
    STAGE_STATUS_OK,
    STAGE_STATUS_UNAVAILABLE,
    run_security_stage,
)
from .core.security.verify import verify_security_outputs
from .core.orchestration.verify import verify_output_dir

logger = logging.getLogger(__name__)

_EXIT_OK = 0
_EXIT_ERROR = 1
_EXIT_ALL_SOURCES_FAILED = 2
_EXIT_PUBLISH_GUARDED = 3
_EXIT_SECURITY_UNAVAILABLE = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auto-subscription-engine",
        description=(
            "Aggregate public proxy subscription sources into one normalized, "
            "deduplicated subscription. No VPS, no Cloudflare."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser(
        "run", help="run the aggregation pipeline (default command)"
    )
    run_parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/sources.yaml"),
        help="path to the sources YAML config (default: config/sources.yaml)",
    )
    run_parser.add_argument(
        "--discovery-config",
        type=Path,
        default=Path("config/discovery.yaml"),
        help="path to discovery policy YAML (default: config/discovery.yaml)",
    )
    run_parser.add_argument(
        "--discovery-state",
        type=Path,
        default=Path("data/discovery.json"),
        help="persistent credential-free source intelligence (default: data/discovery.json)",
    )
    run_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="directory for generated outputs (default: output)",
    )
    run_parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="per-request timeout in seconds (default: 15)",
    )
    run_parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="number of retries per source (default: 2)",
    )
    run_parser.add_argument(
        "--from-file",
        type=Path,
        default=None,
        help="offline mode: process a local raw subscription file instead of fetching",
    )
    run_parser.add_argument(
        "--quiet", action="store_true", help="reduce logging to warnings only"
    )

    verify_parser = subparsers.add_parser(
        "verify", help="validate previously generated outputs"
    )
    verify_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="directory containing the outputs (default: output)",
    )

    core_parser = subparsers.add_parser(
        "core-install",
        help="download and verify the pinned sing-box core (Task 2)",
    )
    core_parser.add_argument(
        "--dest",
        type=Path,
        default=Path(".core-bin"),
        help="installation directory (default: .core-bin, gitignored)",
    )
    core_parser.add_argument(
        "--testing-config",
        type=Path,
        default=Path("config/testing.yaml"),
        help="path to the testing YAML config (default: config/testing.yaml)",
    )
    core_parser.add_argument(
        "--quiet", action="store_true", help="reduce logging to warnings only"
    )

    live_parser = subparsers.add_parser(
        "live",
        help="run the real connectivity pipeline end-to-end (Task 2)",
    )
    live_parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/sources.yaml"),
        help="path to the sources YAML config (default: config/sources.yaml)",
    )
    live_parser.add_argument(
        "--discovery-config",
        type=Path,
        default=Path("config/discovery.yaml"),
        help="path to discovery policy YAML (default: config/discovery.yaml)",
    )
    live_parser.add_argument(
        "--discovery-state",
        type=Path,
        default=Path("data/discovery.json"),
        help="persistent credential-free source intelligence (default: data/discovery.json)",
    )
    live_parser.add_argument(
        "--testing-config",
        type=Path,
        default=Path("config/testing.yaml"),
        help="path to the testing YAML config (default: config/testing.yaml)",
    )
    live_parser.add_argument(
        "--ip-hunter-config",
        type=Path,
        default=Path("config/ip_hunter.yaml"),
        help="static-IP hunter policy YAML (default: config/ip_hunter.yaml)",
    )
    live_parser.add_argument(
        "--ip-history",
        type=Path,
        default=Path("data/ip_history.json"),
        help="persistent credential-free DNS/IP history (default: data/ip_history.json)",
    )
    live_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="directory for generated outputs (default: output)",
    )
    live_parser.add_argument(
        "--core-dir",
        type=Path,
        default=Path(".core-bin"),
        help="directory containing checksum-verified pinned cores (default: .core-bin)",
    )
    live_parser.add_argument(
        "--history",
        type=Path,
        default=None,
        help="optional reliability history JSON file (e.g. data/history.json)",
    )
    live_parser.add_argument(
        "--from-file",
        type=Path,
        default=None,
        help="offline candidate mode: process a local raw subscription file",
    )
    live_parser.add_argument(
        "--preflight-budget",
        type=int,
        default=None,
        help="override scheduler.preflight_budget from the testing config",
    )
    live_parser.add_argument(
        "--runtime-budget",
        type=int,
        default=None,
        help="override scheduler.runtime_budget from the testing config",
    )
    live_parser.add_argument(
        "--max-live-nodes",
        type=int,
        default=None,
        help="override selection.max_live_nodes from the testing config",
    )
    live_parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="per-request source fetch timeout in seconds (default: 15)",
    )
    live_parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="number of retries per source (default: 2)",
    )
    live_parser.add_argument(
        "--quiet", action="store_true", help="reduce logging to warnings only"
    )

    verify_live_parser = subparsers.add_parser(
        "verify-live",
        help="validate Task 2 live outputs (live_*.json, best.txt, countries)",
    )
    verify_live_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="directory containing the live outputs (default: output)",
    )

    publish_parser = subparsers.add_parser(
        "publish",
        help="guarded, transactional publish of live outputs to public/ (Task 3)",
    )
    publish_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="directory containing the Task 2 live outputs (default: output)",
    )
    publish_parser.add_argument(
        "--public-dir",
        type=Path,
        default=Path("public"),
        help="published output directory committed to main (default: public)",
    )
    publish_parser.add_argument(
        "--staging-dir",
        type=Path,
        default=None,
        help=(
            "staging directory for the transactional publish "
            "(default: <public-dir>.staging next to the public dir)"
        ),
    )
    publish_parser.add_argument(
        "--history",
        type=Path,
        default=Path("data/history.json"),
        help="reliability history file (default: data/history.json)",
    )
    publish_parser.add_argument(
        "--history-baseline-file",
        type=Path,
        default=None,
        help=(
            "snapshot of the committed history taken before the pipeline ran; "
            "used for the meaningful-diff decision"
        ),
    )
    publish_parser.add_argument(
        "--security-cache-baseline-dir",
        type=Path,
        default=None,
        help=(
            "snapshot directory of data/security taken before the pipeline "
            "ran; used for the cache meaningful-diff decision"
        ),
    )
    publish_parser.add_argument(
        "--testing-config",
        type=Path,
        default=Path("config/testing.yaml"),
        help="path to the testing YAML config (default: config/testing.yaml)",
    )
    publish_parser.add_argument(
        "--min-live-nodes",
        type=int,
        default=None,
        help="override publish.min_live_nodes from the testing config",
    )
    publish_parser.add_argument(
        "--max-drop-ratio",
        type=float,
        default=None,
        help="override publish.max_drop_ratio from the testing config",
    )
    publish_parser.add_argument(
        "--engine-commit",
        type=str,
        default=None,
        help="short engine commit SHA recorded in status.json / live_stats.json",
    )
    publish_parser.add_argument(
        "--quiet", action="store_true", help="reduce logging to warnings only"
    )

    verify_publish_parser = subparsers.add_parser(
        "verify-publish",
        help="validate the published public/ tree (Task 3)",
    )
    verify_publish_parser.add_argument(
        "--public-dir",
        type=Path,
        default=Path("public"),
        help="published output directory (default: public)",
    )

    security_parser = subparsers.add_parser(
        "security-check",
        help=(
            "run the Security Deep Check on LIVE outputs and rewrite them "
            "security-filtered (Task 4)"
        ),
    )
    security_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="directory containing the Task 2 live outputs (default: output)",
    )
    security_parser.add_argument(
        "--testing-config",
        type=Path,
        default=Path("config/testing.yaml"),
        help="path to the testing YAML config (default: config/testing.yaml)",
    )
    security_parser.add_argument(
        "--core-dir",
        type=Path,
        default=Path(".core-bin"),
        help="directory containing checksum-verified pinned cores (default: .core-bin)",
    )
    security_parser.add_argument(
        "--security-cache-dir",
        type=Path,
        default=None,
        help="feed cache directory (default: data/security/feeds)",
    )
    security_parser.add_argument(
        "--quiet", action="store_true", help="reduce logging to warnings only"
    )

    verify_security_parser = subparsers.add_parser(
        "verify-security",
        help="validate the security-filtered outputs before publish (Task 4)",
    )
    verify_security_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="directory containing the live outputs (default: output)",
    )
    verify_security_parser.add_argument(
        "--testing-config",
        type=Path,
        default=Path("config/testing.yaml"),
        help="path to the testing YAML config (default: config/testing.yaml)",
    )

    cores_parser = subparsers.add_parser(
        "cores-install",
        help="install ALL pinned cores (sing-box, xray, hiddify, mihomo)",
    )
    cores_parser.add_argument(
        "--dest",
        type=Path,
        default=Path(".core-bin"),
        help="installation directory (default: .core-bin, gitignored)",
    )
    cores_parser.add_argument(
        "--testing-config",
        type=Path,
        default=Path("config/testing.yaml"),
        help="path to the testing YAML config (default: config/testing.yaml)",
    )
    cores_parser.add_argument(
        "--summary-json",
        type=Path,
        default=None,
        help="optional path for the credential-free install summary JSON",
    )
    cores_parser.add_argument(
        "--quiet", action="store_true", help="reduce logging to warnings only"
    )

    compat_parser = subparsers.add_parser(
        "compat-check",
        help=(
            "run the multi-core client compatibility stage on the "
            "security-publishable LIVE set (universal layer)"
        ),
    )
    compat_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="directory containing the security-filtered live outputs",
    )
    compat_parser.add_argument(
        "--testing-config",
        type=Path,
        default=Path("config/testing.yaml"),
        help="path to the testing YAML config (default: config/testing.yaml)",
    )
    compat_parser.add_argument(
        "--core-dir",
        type=Path,
        default=Path(".core-bin"),
        help="directory containing checksum-verified pinned cores (default: .core-bin)",
    )
    compat_parser.add_argument(
        "--discovery-state",
        type=Path,
        default=Path("data/discovery.json"),
        help="persistent source intelligence JSON (default: data/discovery.json)",
    )
    compat_parser.add_argument(
        "--history",
        type=Path,
        default=None,
        help="optional reliability history JSON file (per-core records)",
    )
    compat_parser.add_argument(
        "--quiet", action="store_true", help="reduce logging to warnings only"
    )

    verify_compat_parser = subparsers.add_parser(
        "verify-compat",
        help="validate the multi-core compatibility outputs before publish",
    )
    verify_compat_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="directory containing the compatibility outputs",
    )

    score_parser = subparsers.add_parser(
        "score-check",
        help="attach Stage-9 multidimensional scorecards to verified nodes",
    )
    score_parser.add_argument("--output-dir", type=Path, default=Path("output"))
    score_parser.add_argument("--testing-config", type=Path, default=Path("config/testing.yaml"))
    score_parser.add_argument("--history", type=Path, default=Path("data/history.json"))
    score_parser.add_argument("--operator-state", type=Path, default=Path("data/operator_probes.json"))
    score_parser.add_argument("--operator-config", type=Path, default=Path("config/operator_probes.yaml"))

    verify_score_parser = subparsers.add_parser(
        "verify-score",
        help="validate Stage-9 multidimensional score outputs",
    )
    verify_score_parser.add_argument("--output-dir", type=Path, default=Path("output"))


    feed_parser = subparsers.add_parser(
        "feed-build",
        help="build Stage-10 score-aware client/network/operator feeds",
    )
    feed_parser.add_argument("--output-dir", type=Path, default=Path("output"))
    feed_parser.add_argument("--config", type=Path, default=Path("config/feeds.yaml"))

    verify_feed_parser = subparsers.add_parser(
        "verify-feed",
        help="validate Stage-10 feed outputs before guarded publish",
    )
    verify_feed_parser.add_argument("--output-dir", type=Path, default=Path("output"))

    production_parser = subparsers.add_parser(
        "production-check",
        help="run the Stage-11 production release gate before commit/push",
    )
    production_parser.add_argument("--repo-root", type=Path, default=Path("."))
    production_parser.add_argument("--output-dir", type=Path, default=Path("output"))
    production_parser.add_argument("--public-dir", type=Path, default=Path("public"))
    production_parser.add_argument(
        "--report", type=Path, default=Path("output/production_health.json")
    )
    production_parser.add_argument(
        "--max-state-bytes", type=int, default=64 * 1024 * 1024
    )

    probe_job_parser = subparsers.add_parser(
        "operator-probe-job",
        help="build a signed, expiring job for a self-hosted operator probe",
    )
    probe_job_parser.add_argument("--input", type=Path, required=True, help="plain share-URI candidate file")
    probe_job_parser.add_argument("--operator-profile", required=True, help="profile key from config/operator_probes.yaml")
    probe_job_parser.add_argument("--output", type=Path, required=True, help="signed job envelope output")
    probe_job_parser.add_argument("--operator-config", type=Path, default=Path("config/operator_probes.yaml"))
    probe_job_parser.add_argument("--secret-env", default="ASE_OPERATOR_PROBE_SECRET", help="environment variable holding the HMAC secret")
    probe_job_parser.add_argument("--key-id", default=None, help="non-secret signing key identifier")
    probe_job_parser.add_argument("--runner-label", default=None, help="optional self-hosted runner label; must match the configured profile")
    probe_job_parser.add_argument("--limit", type=int, default=None, help="override max candidates per job")

    probe_ingest_parser = subparsers.add_parser(
        "operator-probe-ingest",
        help="verify and ingest one signed operator-probe result",
    )
    probe_ingest_parser.add_argument("--input", type=Path, required=True, help="signed result envelope")
    probe_ingest_parser.add_argument("--operator-profile", required=True, help="expected operator profile")
    probe_ingest_parser.add_argument("--state", type=Path, default=Path("data/operator_probes.json"))
    probe_ingest_parser.add_argument("--operator-config", type=Path, default=Path("config/operator_probes.yaml"))
    probe_ingest_parser.add_argument("--secret-env", default="ASE_OPERATOR_PROBE_SECRET", help="environment variable holding the HMAC secret")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw:
        # No arguments at all: default to "run" with default options.
        raw = ["run"]
    args = parser.parse_args(raw)
    logging.basicConfig(
        level=logging.WARNING if getattr(args, "quiet", False) else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.command == "verify":
        return _cmd_verify(args)
    if args.command == "core-install":
        return _cmd_core_install(args)
    if args.command == "live":
        return _cmd_live(args)
    if args.command == "verify-live":
        return _cmd_verify_live(args)
    if args.command == "publish":
        return _cmd_publish(args)
    if args.command == "verify-publish":
        return _cmd_verify_publish(args)
    if args.command == "security-check":
        return _cmd_security_check(args)
    if args.command == "verify-security":
        return _cmd_verify_security(args)
    if args.command == "cores-install":
        return _cmd_cores_install(args)
    if args.command == "compat-check":
        return _cmd_compat_check(args)
    if args.command == "verify-compat":
        return _cmd_verify_compat(args)
    if args.command == "score-check":
        return _cmd_score_check(args)
    if args.command == "verify-score":
        return _cmd_verify_score(args)
    if args.command == "feed-build":
        return _cmd_feed_build(args)
    if args.command == "verify-feed":
        return _cmd_verify_feed(args)
    if args.command == "production-check":
        return _cmd_production_check(args)
    if args.command == "operator-probe-job":
        return _cmd_operator_probe_job(args)
    if args.command == "operator-probe-ingest":
        return _cmd_operator_probe_ingest(args)
    return _cmd_run(args)


def _cmd_run(args: argparse.Namespace) -> int:
    options = RunOptions(
        config_path=args.config,
        output_dir=args.output_dir,
        timeout=args.timeout,
        retries=args.retries,
        from_file=args.from_file,
        discovery_config_path=args.discovery_config,
        discovery_state_path=args.discovery_state,
    )
    try:
        stats = run_pipeline(options)
    except SourceConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_ERROR

    for line in summarize(stats):
        print(line)

    if (
        options.from_file is None
        and stats["sources_total"] > 0
        and stats["sources_success"] == 0
    ):
        print(
            "error: all sources failed — refusing to report success",
            file=sys.stderr,
        )
        return _EXIT_ALL_SOURCES_FAILED
    return _EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    problems = verify_output_dir(args.output_dir)
    if problems:
        for problem in problems:
            print(f"problem: {problem}", file=sys.stderr)
        return _EXIT_ERROR
    print(f"outputs in {args.output_dir} are valid")
    return _EXIT_OK


def _cmd_core_install(args: argparse.Namespace) -> int:
    """Install only the pinned sing-box core through the unified installer."""
    try:
        tc = load_testing_config(args.testing_config)
        spec = specs_from_testing_config(tc).get("singbox")
        if spec is None:
            raise CoreInstallError("singbox is not pinned in testing config")
        path = install_core_binary(args.dest, spec)
    except (SystemicPipelineError, CoreInstallError) as exc:
        print(f"error: core install failed: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    print(f"pinned core installed and checksum-verified: {path}")
    return _EXIT_OK


def _cmd_live(args: argparse.Namespace) -> int:
    options = LiveOptions(
        config_path=args.config,
        testing_config_path=args.testing_config,
        output_dir=args.output_dir,
        core_dir=args.core_dir,
        history_path=args.history,
        discovery_config_path=args.discovery_config,
        discovery_state_path=args.discovery_state,
        ip_hunter_config_path=args.ip_hunter_config,
        ip_history_path=args.ip_history,
        from_file=args.from_file,
        timeout=args.timeout,
        retries=args.retries,
        preflight_budget=args.preflight_budget,
        runtime_budget=args.runtime_budget,
        max_live_nodes=args.max_live_nodes,
    )
    try:
        stats = run_live_pipeline(options)
    except (SystemicPipelineError, SourceConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_ERROR

    print(f"preflight candidates scheduled: {stats['candidates_sampled']}")
    hunter_stats = stats.get("ip_hunter", {})
    if isinstance(hunter_stats, dict) and hunter_stats.get("enabled"):
        print(
            "static-IP variants: "
            f"{hunter_stats.get('variants_created', 0)} "
            f"from {hunter_stats.get('hosts_resolved', 0)} resolved hostnames"
        )
    print(f"tcp endpoints tested/passed: {stats['tcp_tested']}/{stats['tcp_passed']}")
    print(f"proxy configs tested/live: {stats['proxy_tested']}/{stats['proxy_live']}")
    print(f"live nodes selected: {stats['live_selected']} of {stats['live_total']}")
    print(f"countries discovered: {stats['countries_discovered']}")
    print(f"runtime: {stats['runtime_seconds']}s")
    if stats["status"] == "zero_live":
        print(
            "warning: zero LIVE nodes found - see live_diagnostics.json",
            file=sys.stderr,
        )
    # Machine-readable stats for CI log extraction (credential-free).
    print("LIVE_STATS_JSON=" + json.dumps(stats, ensure_ascii=False))
    return _EXIT_OK


def _cmd_verify_live(args: argparse.Namespace) -> int:
    problems = verify_live_outputs(args.output_dir)
    if problems:
        for problem in problems:
            print(f"problem: {problem}", file=sys.stderr)
        return _EXIT_ERROR
    print(f"live outputs in {args.output_dir} are valid")
    return _EXIT_OK


def _cmd_publish(args: argparse.Namespace) -> int:
    try:
        tc = load_testing_config(args.testing_config)
    except SystemicPipelineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    publish_cfg = tc.get("publish", {})
    security_cfg = tc.get("security", {})
    compatibility_cfg = tc.get("compatibility", {})
    min_live = int(
        args.min_live_nodes
        if args.min_live_nodes is not None
        else publish_cfg.get("min_live_nodes", 5)
    )
    max_drop = float(
        args.max_drop_ratio
        if args.max_drop_ratio is not None
        else publish_cfg.get("max_drop_ratio", 0.80)
    )
    min_publishable = int(
        security_cfg.get("min_publishable_nodes", 5)
        if isinstance(security_cfg, dict) else 5
    )
    min_universal = int(
        compatibility_cfg.get("min_universal_nodes", 1)
        if isinstance(compatibility_cfg, dict) else 1
    )
    cache_baseline = None
    if args.security_cache_baseline_dir is not None:
        from .core.hardening.publication import snapshot_security_cache

        cache_baseline = snapshot_security_cache(args.security_cache_baseline_dir)
    staging_dir = args.staging_dir or Path(str(args.public_dir) + ".staging")
    options = PublishOptions(
        output_dir=args.output_dir,
        public_dir=args.public_dir,
        staging_dir=staging_dir,
        history_path=args.history,
        history_baseline_text=resolve_history_baseline(
            args.history, args.history_baseline_file, repo_root=Path.cwd()
        ),
        min_live_nodes=min_live,
        max_drop_ratio=max_drop,
        min_publishable_nodes=min_publishable,
        min_universal_nodes=min_universal,
        security_cache_dir=Path("data/security"),
        security_cache_baseline=cache_baseline,
        engine_commit=args.engine_commit,
    )
    try:
        result = run_publish(options)
    except PublishError as exc:
        print(f"error: publish failed, previous public output preserved: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    print(f"publish decision: {result.decision}")
    for reason in result.reasons:
        print(f"reason: {reason}")
    print(f"live nodes: {result.live_count} (previous: {result.previous_count})")
    print(f"commit recommended: {result.commit_recommended}")
    # Machine-readable decision for CI steps (credential-free).
    print(
        "PUBLISH_JSON="
        + json.dumps(
            {
                "decision": result.decision,
                "commit_recommended": result.commit_recommended,
                "commit_message": result.commit_message,
                "live_count": result.live_count,
                "previous_count": result.previous_count,
                "meaningful_changes": result.meaningful_changes,
            },
            ensure_ascii=False,
        )
    )
    if result.decision == "skipped_invalid_output":
        return _EXIT_ERROR
    if result.decision.startswith("skipped_"):
        return _EXIT_PUBLISH_GUARDED
    return _EXIT_OK


def _cmd_verify_publish(args: argparse.Namespace) -> int:
    problems = verify_public_dir(args.public_dir)
    if problems:
        for problem in problems:
            print(f"problem: {problem}", file=sys.stderr)
        return _EXIT_ERROR
    print(f"published outputs in {args.public_dir} are valid")
    return _EXIT_OK


def _cmd_security_check(args: argparse.Namespace) -> int:
    """Task 4: security deep check; rewrites outputs security-filtered."""
    options = SecurityOptions(
        output_dir=args.output_dir,
        testing_config_path=args.testing_config,
        core_dir=args.core_dir,
        security_cache_dir=args.security_cache_dir,
    )
    try:
        result = run_security_stage(options)
    except (OSError, ValueError) as exc:
        print(f"error: security stage failed: {exc}", file=sys.stderr)
        return _EXIT_ERROR

    print(f"security stage status: {result.status}")
    if result.status == STAGE_STATUS_UNAVAILABLE:
        print(f"reason: {result.reason}")
        print(
            "SECURITY_JSON="
            + json.dumps(
                {"status": result.status, "reason": result.reason},
                ensure_ascii=False,
            )
        )
        print(
            "error: required security intelligence unavailable - "
            "publishing is halted and the previous healthy output is kept",
            file=sys.stderr,
        )
        return _EXIT_SECURITY_UNAVAILABLE
    if result.status == STAGE_STATUS_OK:
        print(
            "SECURITY_JSON="
            + json.dumps(
                {
                    "status": result.status,
                    "live_total": result.live_total,
                    "publishable_total": result.publishable_total,
                    "selected_total": result.selected_total,
                    "feed_statuses": result.feed_statuses,
                    "feed_age_hours": result.feed_age_hours,
                },
                ensure_ascii=False,
            )
        )
    return _EXIT_OK


def _cmd_verify_security(args: argparse.Namespace) -> int:
    problems = verify_security_outputs(args.output_dir, args.testing_config)
    if problems:
        for problem in problems:
            print(f"problem: {problem}", file=sys.stderr)
        return _EXIT_ERROR
    print(f"security-filtered outputs in {args.output_dir} are valid")
    return _EXIT_OK


# ---------------------------------------------------------------------------
# Multi-core compatibility layer commands
# ---------------------------------------------------------------------------

_EXIT_COMPAT_SYSTEMIC = 5


def _cmd_cores_install(args: argparse.Namespace) -> int:
    """Install every pinned core with independent checksum verification.

    Stage 7 has no privileged base core: the run can continue with any
    checksum-verified compatible core.  The command fails only when none of
    the pinned cores can be installed.
    """
    summary: dict = {"cores": {}}
    try:
        tc = load_testing_config(args.testing_config)
        specs = specs_from_testing_config(tc)
    except (SystemicPipelineError, CoreInstallError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_ERROR

    for key in ("singbox", "xray", "hiddify", "mihomo"):
        spec = specs.get(key)
        if spec is None:
            summary["cores"][key] = {"ok": False, "error": "not_pinned_in_config"}
            print(f"warning: core {key} is not pinned in the testing config", file=sys.stderr)
            continue
        try:
            binary = install_core_binary(args.dest, spec)
            summary["cores"][key] = {
                "ok": True, "version": spec.version, "binary": str(binary)
            }
            print(f"pinned core {key} {spec.version} installed and checksum-verified: {binary}")
        except CoreInstallError as exc:
            summary["cores"][key] = {"ok": False, "error": str(exc)}
            print(f"warning: core {key} install failed: {exc}", file=sys.stderr)

    if args.summary_json is not None:
        args.summary_json.parent.mkdir(parents=True, exist_ok=True)
        args.summary_json.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    missing = [key for key, item in summary["cores"].items() if not item.get("ok")]
    available = [key for key, item in summary["cores"].items() if item.get("ok")]
    if missing:
        print(f"cores unavailable this run (their client feeds are not published): {sorted(missing)}")
    if not available:
        print("error: no checksum-verified core could be installed", file=sys.stderr)
        return _EXIT_ERROR
    return _EXIT_OK


def _cmd_compat_check(args: argparse.Namespace) -> int:
    from .core.clients.compatibility import CompatOptions, run_compat_stage
    from .core.clients.compatibility.engine import STAGE_STATUS_DISABLED

    try:
        tc = load_testing_config(args.testing_config)
        core_paths = verified_core_paths(args.core_dir, tc)
    except (SystemicPipelineError, CoreInstallError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_COMPAT_SYSTEMIC
    options = CompatOptions(
        output_dir=args.output_dir,
        testing_config_path=args.testing_config,
        core_paths=core_paths,
        history_path=args.history,
        discovery_state_path=args.discovery_state,
    )
    try:
        result = run_compat_stage(options)
    except Exception as exc:  # systemic: unreadable outputs / broken config
        print(f"error: compatibility stage failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return _EXIT_COMPAT_SYSTEMIC
    if result.status == STAGE_STATUS_DISABLED:
        print("compatibility layer disabled by configuration")
        return _EXIT_OK

    print(f"compat checked nodes: {result.checked_total}")
    print(f"universal-compatible nodes: {result.universal_total}")
    for feed, count in sorted(result.feed_counts.items()):
        print(f"feed {feed}: {count}")
    for core, status in sorted(result.core_statuses.items()):
        print(f"core {core}: {status}")
    stats_path = args.output_dir / "live_stats.json"
    if stats_path.is_file():
        stats = json.loads(stats_path.read_text(encoding="utf-8"))
        print("COMPAT_JSON=" + json.dumps(
            {
                "status": result.status,
                "checked": result.checked_total,
                "universal": result.universal_total,
                "feed_counts": result.feed_counts,
                "core_statuses": result.core_statuses,
                "compatibility": stats.get("compatibility"),
            },
            ensure_ascii=False,
        ))
    return _EXIT_OK


def _cmd_verify_compat(args: argparse.Namespace) -> int:
    from .core.clients.compatibility.verify import verify_compat_outputs

    problems = verify_compat_outputs(args.output_dir)
    if problems:
        for problem in problems:
            print(f"problem: {problem}", file=sys.stderr)
        return _EXIT_ERROR
    print(f"compatibility outputs in {args.output_dir} are valid")
    return _EXIT_OK


def _probe_secret(env_name: str) -> str:
    value = os.environ.get(env_name, "")
    if not value:
        raise ValueError(f"{env_name} is empty")
    return value


def _cmd_score_check(args: argparse.Namespace) -> int:
    try:
        stats = run_scoring_stage(ScoringOptions(
            output_dir=args.output_dir,
            testing_config_path=args.testing_config,
            history_path=args.history,
            operator_state_path=args.operator_state,
            operator_config_path=args.operator_config,
        ))
    except (OSError, ValueError) as exc:
        print(f"error: scoring stage failed: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    print(f"Stage-9 scored nodes: {stats['scored_nodes']}")
    print(f"global median score: {stats['global_score_median']}")
    print("SCORING_V2_JSON=" + json.dumps(stats, ensure_ascii=False))
    return _EXIT_OK


def _cmd_verify_score(args: argparse.Namespace) -> int:
    problems = verify_scoring_outputs(args.output_dir)
    if problems:
        for problem in problems:
            print(f"problem: {problem}", file=sys.stderr)
        return _EXIT_ERROR
    print(f"Stage-9 scoring outputs in {args.output_dir} are valid")
    return _EXIT_OK


def _cmd_feed_build(args: argparse.Namespace) -> int:
    try:
        manifest = run_feed_stage(FeedOptions(output_dir=args.output_dir, config_path=args.config))
    except (OSError, ValueError) as exc:
        print(f"error: feed stage failed: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    counts = manifest.get("feed_counts", {})
    print(f"Stage-10 feeds built: {len(counts)}")
    print("FEED_ENGINE_JSON=" + json.dumps(manifest, ensure_ascii=False))
    return _EXIT_OK


def _cmd_verify_feed(args: argparse.Namespace) -> int:
    problems = verify_feed_outputs(args.output_dir)
    if problems:
        for problem in problems:
            print(f"problem: {problem}", file=sys.stderr)
        return _EXIT_ERROR
    print(f"Stage-10 feed outputs in {args.output_dir} are valid")
    return _EXIT_OK


def _cmd_production_check(args: argparse.Namespace) -> int:
    try:
        report = run_release_gate(
            repo_root=args.repo_root,
            output_dir=args.output_dir,
            public_dir=args.public_dir,
            max_state_bytes=max(1024, int(args.max_state_bytes)),
        )
        write_release_gate_report(args.report, report)
    except (OSError, ValueError) as exc:
        print(f"error: production gate failed: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    for item in report.checks:
        label = "PASS" if item.passed else "FAIL"
        print(f"[{label}] {item.name}: {item.detail}")
    print(f"production gate: {report.status}")
    return _EXIT_OK if report.passed else _EXIT_ERROR


def _cmd_operator_probe_job(args: argparse.Namespace) -> int:
    try:
        cfg = load_operator_probe_config(args.operator_config)
        profile = cfg.profiles.get(args.operator_profile)
        if profile is None or not profile.enabled:
            raise ValueError(f"operator profile is unavailable: {args.operator_profile}")
        if args.runner_label is not None and args.runner_label != profile.runner_label:
            raise ValueError(
                f"runner label mismatch: expected {profile.runner_label}, got {args.runner_label}"
            )
        secret = _probe_secret(args.secret_env)
        uris = read_candidate_uris(args.input)
        limit = args.limit if args.limit is not None else cfg.policy.max_candidates_per_job
        job = build_probe_job(
            uris,
            operator_profile=args.operator_profile,
            ttl_minutes=cfg.policy.job_ttl_minutes,
            limit=limit,
        )
        if not job.candidates:
            raise ValueError("operator probe job has no valid candidates")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_signed_probe_job(
            job, args.output, key_id=args.key_id or args.operator_profile, secret=secret
        )
    except (OSError, ValueError) as exc:
        print(f"error: operator probe job failed: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    print(f"operator probe job: {job.job_id} ({len(job.candidates)} candidates, {profile.display_name})")
    return _EXIT_OK


def _cmd_operator_probe_ingest(args: argparse.Namespace) -> int:
    try:
        cfg = load_operator_probe_config(args.operator_config)
        if args.operator_profile not in cfg.profiles:
            raise ValueError(f"unknown operator profile: {args.operator_profile}")
        secret = _probe_secret(args.secret_env)
        envelope = json.loads(args.input.read_text(encoding="utf-8"))
        store = OperatorProbeStore(args.state)
        summary = store.ingest_signed_result(
            envelope,
            secret=secret,
            expected_operator=args.operator_profile,
            max_age_minutes=cfg.policy.result_max_age_minutes,
            processed_limit=cfg.policy.processed_result_ids,
        )
        store.prune(
            retention_days=cfg.policy.history_retention_days,
            max_nodes=cfg.policy.max_nodes,
        )
        store.save()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: operator probe ingest failed: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    print("OPERATOR_PROBE_JSON=" + json.dumps(summary, sort_keys=True))
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
