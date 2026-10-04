"""Task 3: guarded, transactional publishing of live outputs.

The GitHub Action runs this after the Task 2 live pipeline succeeded.
Publishing is *transactional* — the previous healthy ``public/`` tree must
survive any failure — so the flow always is:

1. plan   — verify the Task 2 outputs, read the new/previous node counts,
            evaluate the safety guards (zero-live, minimum-live,
            catastrophic drop ratio).  No files are touched here.
2. stage  — build a complete ``public/`` tree in a staging directory
            (never in place), including ``status.json`` and injected
            publish metadata in ``live_stats.json``.
3. verify — validate the staged tree (base64 match, LIVE-only content,
            no URIs / UUIDs / secrets in the metadata JSON files).
4. promote— atomically swap the staging directory into ``public/``
            (rename-based; rollback on failure).  This also removes
            stale country files: the published ``countries/`` directory
            is exactly the new run's country set.
5. decide — a commit is recommended only when a *meaningful* change
            exists: subscription/best/country content changed, or the
            reliability history moved beyond volatile bookkeeping.
            Volatile fields (``generated_at``, runtimes, publish
            timestamps) never trigger a commit.

Failure safety: if any guard or verification fails, ``public/`` is not
modified at all — the last healthy subscription stays published.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ..orchestration.live import verify_live_outputs

logger = logging.getLogger(__name__)

# -- decisions -----------------------------------------------------------------

DECISION_PUBLISHED = "published"
DECISION_SKIPPED_ZERO_LIVE = "skipped_zero_live"
DECISION_SKIPPED_MIN_LIVE = "skipped_min_live"
DECISION_SKIPPED_DROP_RATIO = "skipped_drop_ratio"
DECISION_SKIPPED_INVALID_OUTPUT = "skipped_invalid_output"
DECISION_SKIPPED_MIN_SECURITY = "skipped_min_security"
DECISION_SKIPPED_SECURITY_UNAVAILABLE = "skipped_security_unavailable"
DECISION_SKIPPED_MIN_UNIVERSAL = "skipped_min_universal"

#: Guard decisions keep the job "soft-failed" later in the workflow, but
#: they must never overwrite the previous healthy public tree.
GUARD_DECISIONS = frozenset({
    DECISION_SKIPPED_ZERO_LIVE,
    DECISION_SKIPPED_MIN_LIVE,
    DECISION_SKIPPED_DROP_RATIO,
    DECISION_SKIPPED_MIN_SECURITY,
    DECISION_SKIPPED_SECURITY_UNAVAILABLE,
    DECISION_SKIPPED_MIN_UNIVERSAL,
})

MSG_COMMIT_PUBLISH = "chore: refresh live subscription"
MSG_COMMIT_HISTORY = "chore: update reliability history"
MSG_COMMIT_SECURITY_CACHE = "chore: update security intelligence cache"

# -- meaningful-change detection ------------------------------------------------

#: Files whose exact bytes decide whether output changed meaningfully.
#: ``subscription_base64.txt`` is derived from ``subscription.txt`` and the
#: JSON metadata files are volatile (timestamps, scores), so they are
#: intentionally excluded from the diff decision.
PUBLIC_MEANINGFUL_FILES = ("subscription.txt", "best.txt")

#: History entry keys that move on every run without changing node
#: behaviour.  They are written to the file but ignored by the diff
#: decision (monotonic counters and bookkeeping timestamps).
HISTORY_VOLATILE_KEYS = frozenset({
    "checks_total",
    "checks_passed",
    "last_success",
    "last_failure",
    "last_latency_ms",
    "last_seen",
    "first_discovered",
    "last_discovered",
})

#: Proxy URI schemes — must never appear inside metadata JSON files.
_PROXY_URI_SCHEME_RE = re.compile(
    r"\b(vless|vmess|trojan|hysteria2|hy2|ss|socks5?)://", re.IGNORECASE
)
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

_STATUS_REQUIRED_KEYS = ("status", "last_successful_publish", "live_nodes",
                         "engine_version", "core_version")

DEFAULT_MIN_LIVE_NODES = 5
DEFAULT_MAX_DROP_RATIO = 0.80
DEFAULT_MIN_PUBLISHABLE_NODES = 5

#: Cache-relative prefixes under ``data/security/`` whose change counts
#: as a *meaningful* (committable) change: the persisted feed/ASN caches
#: are bounded, verified and credential-free.
SECURITY_CACHE_PREFIX = "data/security/"

#: Suffix of generated base64 feed files (multi-core layer).
FEED_B64_SUFFIX = "_base64.txt"


def _feed_is_empty(raw: bytes) -> bool:
    """True when a staged feed carries no usable content."""
    if not raw.strip():
        return True
    if raw.strip().startswith(b"vmess://") or b"://" in raw.split(b"\n", 1)[0]:
        return not any(line.strip() for line in raw.splitlines())
    return False


def _yaml_feed_is_empty(raw: bytes) -> bool:
    """True when a staged Mihomo YAML carries no proxies."""
    try:
        payload = yaml.safe_load(raw.decode("utf-8")) or {}
    except Exception:  # noqa: BLE001 - corrupt YAML counts as empty
        return True
    if not isinstance(payload, dict):
        return True
    proxies = payload.get("proxies")
    return not isinstance(proxies, list) or len(proxies) == 0


class PublishError(Exception):
    """Raised for structural publishing errors (bad options, I/O)."""


# -- options / result -------------------------------------------------------------


@dataclass
class PublishOptions:
    """Inputs for one publish run (all paths, no credentials)."""

    output_dir: Path
    public_dir: Path
    staging_dir: Path
    history_path: Path | None = None
    #: Serialized JSON of the committed history (from ``git show HEAD:...``
    #: or a pre-pipeline snapshot).  ``None`` means "no baseline known",
    #: which counts as a meaningful change when a new history exists.
    history_baseline_text: str | None = None
    min_live_nodes: int = DEFAULT_MIN_LIVE_NODES
    max_drop_ratio: float = DEFAULT_MAX_DROP_RATIO
    #: Task 4: minimum ALLOW/WARN nodes that must survive security
    #: filtering for the publish to proceed (security minimum guard).
    min_publishable_nodes: int = DEFAULT_MIN_PUBLISHABLE_NODES
    #: Multi-core layer: minimum universal-compatible nodes the main
    #: subscription must contain. A run whose universal feed is empty
    #: must never replace the previous (compatible) subscription.
    min_universal_nodes: int = 1
    #: Directory holding the persistent security cache (data/security).
    security_cache_dir: Path | None = None
    #: Snapshot of ``data/security/`` taken BEFORE the pipeline/security
    #: stage ran (the caller snapshots it, like the history baseline).
    #: ``None``/empty means "nothing committed yet" - any cache content
    #: then counts as a change.
    security_cache_baseline: dict | None = None
    engine_commit: str | None = None
    #: Fixed timestamp for deterministic tests; real runs use "now".
    run_started_at: str | None = None


@dataclass
class PublishResult:
    """Outcome of :func:`run_publish` (credential-free)."""

    decision: str = DECISION_SKIPPED_INVALID_OUTPUT
    reasons: list[str] = field(default_factory=list)
    live_count: int | None = None
    previous_count: int | None = None
    meaningful_changes: list[str] = field(default_factory=list)
    commit_recommended: bool = False
    commit_message: str | None = None
    staged_files: list[str] = field(default_factory=list)


# -- snapshots (pure helpers, easy to test) ---------------------------------------


def snapshot_dir(root: Path) -> dict[str, bytes]:
    """Map of ``relative/path -> bytes`` for every file under ``root``."""
    root = Path(root)
    snap: dict[str, bytes] = {}
    if not root.is_dir():
        return snap
    for path in sorted(root.rglob("*")):
        if path.is_file():
            snap[path.relative_to(root).as_posix()] = path.read_bytes()
    return snap


def meaningful_public_changes(
    old: dict[str, bytes], new: dict[str, bytes]
) -> list[str]:
    """Names of meaningfully changed public files (volatile-only diffs excluded)."""
    changes: list[str] = []
    for name in PUBLIC_MEANINGFUL_FILES:
        if old.get(name) != new.get(name):
            changes.append(f"public/{name}")
    old_countries = {k: v for k, v in old.items() if k.startswith("countries/")}
    new_countries = {k: v for k, v in new.items() if k.startswith("countries/")}
    if old_countries != new_countries:
        changes.append("public/countries/")
    for prefix in ("clients/", "networks/", "profiles/", "operators/"):
        old_sub = {k: v for k, v in old.items() if k.startswith(prefix)}
        new_sub = {k: v for k, v in new.items() if k.startswith(prefix)}
        if old_sub != new_sub:
            changes.append(f"public/{prefix}")
    return changes


def _normalize_history(text: str | None) -> object:
    """Parse history JSON down to its non-volatile shape for diffing."""
    if not text or not text.strip():
        return None
    try:
        raw = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "<invalid>"
    if not isinstance(raw, dict) or not isinstance(raw.get("entries"), dict):
        return "<invalid>"
    normalized: dict[str, object] = {}
    for fingerprint, item in raw["entries"].items():
        if not isinstance(item, dict):
            continue
        kept = {
            key: value
            for key, value in item.items()
            if key not in HISTORY_VOLATILE_KEYS and key != "fingerprint"
        }
        if "rolling_success_rate" in kept:
            try:
                kept["rolling_success_rate"] = round(float(kept["rolling_success_rate"]), 4)
            except (TypeError, ValueError):
                pass
        normalized[fingerprint] = kept
    return normalized


def meaningful_history_changes(old_text: str | None, new_text: str | None) -> bool:
    """True when history moved beyond volatile bookkeeping fields."""
    if _normalize_history(old_text) != _normalize_history(new_text):
        return True
    return False


# -- previous state -----------------------------------------------------------------


def read_previous_live_count(public_dir: Path) -> int | None:
    """``live_selected`` of the last published run, or ``None``.

    A missing or malformed ``public/live_stats.json`` yields ``None`` —
    the run is then treated as a first publish (only ``min_live_nodes``
    applies).  A corrupt previous file must never crash the publish.
    """
    path = Path(public_dir) / "live_stats.json"
    if not path.is_file():
        return None
    try:
        stats = json.loads(path.read_text(encoding="utf-8"))
        count = stats["live_selected"]
        if not isinstance(count, int) or count < 0:
            raise ValueError
        return count
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
        logger.warning("previous public/live_stats.json unreadable - treating as first publish")
        return None


def snapshot_security_cache(cache_dir: Path | None) -> dict[str, bytes]:
    """Snapshot of ``data/security/`` files (relative path -> bytes)."""
    if cache_dir is None:
        return {}
    cache_dir = Path(cache_dir)
    if not cache_dir.is_dir():
        return {}
    snap: dict[str, bytes] = {}
    for path in sorted(cache_dir.rglob("*")):
        if path.is_file():
            snap[path.relative_to(cache_dir).as_posix()] = path.read_bytes()
    return snap


def security_cache_changed(old: dict[str, bytes], new: dict[str, bytes]) -> bool:
    """True when the persisted security cache content actually changed."""
    return old != new


def count_history_entries(history_path: Path | None) -> int:
    """Number of fingerprints in the (new) history file; 0 when absent/corrupt."""
    if history_path is None:
        return 0
    path = Path(history_path)
    if not path.is_file():
        return 0
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        entries = raw.get("entries")
        if isinstance(entries, dict):
            return len(entries)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, AttributeError):
        pass
    return 0


# -- planning ---------------------------------------------------------------------


def plan_publish(options: PublishOptions) -> tuple[PublishResult, dict]:
    """Verify outputs and evaluate guards; returns (result, stats).

    This function never writes — it only decides.  ``stats`` is the parsed
    Task 2 ``live_stats.json`` (only available when the outputs are valid).
    """
    result = PublishResult()
    problems = verify_live_outputs(options.output_dir)
    if problems:
        result.decision = DECISION_SKIPPED_INVALID_OUTPUT
        result.reasons = problems
        return result, {}

    stats = json.loads(
        (Path(options.output_dir) / "live_stats.json").read_text(encoding="utf-8")
    )
    live_count = int(stats.get("live_selected", 0))
    result.live_count = live_count
    previous = read_previous_live_count(options.public_dir)
    result.previous_count = previous

    if live_count == 0:
        result.decision = DECISION_SKIPPED_ZERO_LIVE
        result.reasons = ["no LIVE nodes in this run"]
        return result, {}
    if live_count < options.min_live_nodes:
        result.decision = DECISION_SKIPPED_MIN_LIVE
        result.reasons = [
            f"live nodes {live_count} < publish.min_live_nodes {options.min_live_nodes}"
        ]
        return result, {}
    # Task 4: security feed outage guard — a run whose security stage
    # could not obtain required intelligence must never publish.
    if str(stats.get("security_feed_status", "")) == "unavailable":
        result.decision = DECISION_SKIPPED_SECURITY_UNAVAILABLE
        result.reasons = ["required security intelligence unavailable - publish halted"]
        return result, {}
    # Task 4: security minimum guard — too few nodes survived filtering.
    if "security_checked" in stats and isinstance(
        stats.get("security_publishable"), int
    ):
        publishable = int(stats["security_publishable"])
        if publishable < options.min_publishable_nodes:
            result.decision = DECISION_SKIPPED_MIN_SECURITY
            result.reasons = [
                f"security-publishable nodes {publishable} < "
                f"security.min_publishable_nodes {options.min_publishable_nodes}"
            ]
            return result, {}
    # Multi-core guard: the main subscription is now the universal feed.
    # A run with no verified-universal nodes must never replace it.
    universal_count = stats.get("universal_count")
    if isinstance(universal_count, int) and universal_count < options.min_universal_nodes:
        result.decision = DECISION_SKIPPED_MIN_UNIVERSAL
        result.reasons = [
            f"universal-compatible nodes {universal_count} < "
            f"min_universal_nodes {options.min_universal_nodes} "
            "- previous compatible subscription preserved"
        ]
        return result, {}
    if (
        previous is not None
        and previous > 0
        and float(live_count) < float(previous) * (1.0 - options.max_drop_ratio)
    ):
        result.decision = DECISION_SKIPPED_DROP_RATIO
        result.reasons = [
            f"live nodes {live_count} dropped by more than "
            f"{options.max_drop_ratio:.0%} versus previous publish ({previous})"
        ]
        return result, {}

    result.decision = DECISION_PUBLISHED
    return result, stats


# -- staging -----------------------------------------------------------------------


def _stage_public(options: PublishOptions, stats: dict) -> list[str]:
    """Build the complete public tree inside ``options.staging_dir``."""
    staging = Path(options.staging_dir)
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    output_dir = Path(options.output_dir)

    staged: list[str] = []
    # Task 2 output names -> published public names.
    for src_name, dst_name in (
        ("live_subscription.txt", "subscription.txt"),
        ("live_subscription_base64.txt", "subscription_base64.txt"),
        ("best.txt", "best.txt"),
        ("live_nodes.json", "live_nodes.json"),
    ):
        shutil.copyfile(output_dir / src_name, staging / dst_name)
        staged.append(dst_name)

    # live_stats.json: original content plus publish metadata (still secret-free).
    public_stats = dict(stats)
    public_stats["publish_status"] = "published"
    if options.engine_commit:
        public_stats["engine_commit"] = options.engine_commit
    public_stats["history_entries"] = count_history_entries(options.history_path)
    (staging / "live_stats.json").write_text(
        json.dumps(public_stats, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",newline="\n"
    )
    staged.append("live_stats.json")

    # status.json: tiny health marker for the last successful publish.
    core_version = "unknown"
    effective = stats.get("effective_config")
    if isinstance(effective, dict):
        core_version = str(effective.get("core_version", "unknown"))
    status = {
        "status": "ok",
        "last_successful_publish": options.run_started_at
        or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "live_nodes": int(stats.get("live_selected", 0)),
        "engine_version": options.engine_commit or "unknown",
        "core_version": core_version,
    }
    (staging / "status.json").write_text(
        json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    staged.append("status.json")

    # countries/: exactly this run's countries (stale files disappear on promote).
    countries_src = output_dir / "countries"
    countries_dst = staging / "countries"
    countries_dst.mkdir()
    if countries_src.is_dir():
        for country_file in sorted(countries_src.glob("*.txt")):
            shutil.copyfile(country_file, countries_dst / country_file.name)
            staged.append(f"countries/{country_file.name}")

    # clients/ + networks/ (multi-core layer): staged with per-feed
    # previous-good preservation (spec item 33). A feed that comes back
    # EMPTY (e.g. its core failed validation this run, or every node
    # failed) never replaces a previous non-empty feed. Base64 files are
    # regenerated from the FINAL bytes so equality always holds.
    for sub_name in ("clients", "networks", "profiles"):
        src_dir = output_dir / sub_name
        if not src_dir.is_dir():
            continue
        dst_dir = staging / sub_name
        dst_dir.mkdir()
        prev_dir = Path(options.public_dir) / sub_name
        for feed_file in sorted(src_dir.iterdir()):
            if not feed_file.is_file() or feed_file.name.endswith(FEED_B64_SUFFIX):
                continue
            new_bytes = feed_file.read_bytes()
            if feed_file.suffix == ".yaml" and _yaml_feed_is_empty(new_bytes):
                new_bytes = b""
            if _feed_is_empty(new_bytes):
                prev_file = prev_dir / feed_file.name
                if prev_file.is_file():
                    prev_bytes = prev_file.read_bytes()
                    if not _feed_is_empty(prev_bytes):
                        new_bytes = prev_bytes  # keep the previous good feed
            if not new_bytes:
                continue  # nothing new and nothing preserved: omit the file
            (dst_dir / feed_file.name).write_bytes(new_bytes)
            staged.append(f"{sub_name}/{feed_file.name}")
            if feed_file.suffix == ".txt":
                encoded = base64.b64encode(new_bytes).decode("ascii")
                b64_name = feed_file.stem + FEED_B64_SUFFIX
                (dst_dir / b64_name).write_text(encoded + "\n", encoding="ascii", newline="\n")
                staged.append(f"{sub_name}/{b64_name}")

    # Operator feeds are evidence-fresh by construction. Never preserve stale
    # previous operator artifacts when the current run has no fresh evidence.
    operators_src = output_dir / "operators"
    if operators_src.is_dir():
        operators_dst = staging / "operators"
        shutil.copytree(operators_src, operators_dst, dirs_exist_ok=True)
        for path in sorted(operators_dst.rglob("*")):
            if path.is_file():
                staged.append(path.relative_to(staging).as_posix())

    feed_manifest = output_dir / "feed_manifest.json"
    if feed_manifest.is_file():
        shutil.copyfile(feed_manifest, staging / "feed_manifest.json")
        staged.append("feed_manifest.json")

    problems = verify_public_dir(staging)
    if problems:
        raise PublishError("; ".join(problems))
    return staged


# -- promotion (atomic swap + crash recovery) ---------------------------------------


def _fsync_directory(path: Path) -> None:
    """Best-effort durability barrier for rename operations."""
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def recover_publish_transaction(public_dir: Path, staging_dir: Path) -> list[str]:
    """Recover an interrupted rename transaction before a new publish run.

    A crash can occur after ``public/`` was renamed to ``.public.old-*`` but
    before the verified staging tree was promoted.  In that case the previous
    healthy tree is restored.  A stale staging tree is never trusted across
    runs; it is removed and rebuilt from verified outputs.
    """
    public_dir = Path(public_dir)
    staging_dir = Path(staging_dir)
    parent = public_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    actions: list[str] = []
    backups = sorted(
        parent.glob(f".{public_dir.name}.old-*"),
        key=lambda item: (item.stat().st_mtime_ns, item.name),
    )

    if public_dir.exists():
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
            actions.append("removed_stale_staging")
        for backup in backups:
            shutil.rmtree(backup, ignore_errors=True)
            actions.append("removed_stale_backup")
        if actions:
            _fsync_directory(parent)
        return actions

    if backups:
        restore = backups[-1]
        os.replace(restore, public_dir)
        _fsync_directory(parent)
        actions.append("restored_previous_public")
        for backup in backups[:-1]:
            shutil.rmtree(backup, ignore_errors=True)
            actions.append("removed_stale_backup")

    if staging_dir.exists():
        shutil.rmtree(staging_dir)
        actions.append("removed_stale_staging")
        _fsync_directory(parent)
    return actions


def promote_public(staging_dir: Path, public_dir: Path) -> None:
    """Atomically replace ``public_dir`` with ``staging_dir``.

    The swap is rename-based: either the old or the new tree exists, never
    a partial mixture.  If the second rename fails, the old tree is rolled
    back.  Both directories must live on the same filesystem (the CLI puts
    the staging dir next to the public dir for that reason).
    """
    staging_dir = Path(staging_dir)
    public_dir = Path(public_dir)
    if not staging_dir.is_dir():
        raise PublishError(f"staging directory missing: {staging_dir}")
    public_dir.parent.mkdir(parents=True, exist_ok=True)
    try:
        if staging_dir.stat().st_dev != public_dir.parent.stat().st_dev:
            raise PublishError("staging and public directories must be on the same filesystem")
    except OSError as exc:
        raise PublishError(f"cannot inspect publish filesystem: {exc}") from exc

    if public_dir.exists():
        trash = public_dir.with_name(f".{public_dir.name}.old-{os.getpid()}")
        os.replace(public_dir, trash)
        _fsync_directory(public_dir.parent)
        try:
            os.replace(staging_dir, public_dir)
            _fsync_directory(public_dir.parent)
        except OSError:
            os.replace(trash, public_dir)  # rollback: keep previous good output
            _fsync_directory(public_dir.parent)
            raise
        shutil.rmtree(trash, ignore_errors=True)
        _fsync_directory(public_dir.parent)
    else:
        os.replace(staging_dir, public_dir)
        _fsync_directory(public_dir.parent)


# -- public-tree verification ----------------------------------------------------------


def verify_public_dir(public_dir: Path) -> list[str]:
    """Validate a staged *or* published public tree (empty list = valid)."""
    problems: list[str] = []
    public_dir = Path(public_dir)
    if not public_dir.is_dir():
        return [f"public directory not found: {public_dir}"]

    required = (
        "subscription.txt",
        "subscription_base64.txt",
        "best.txt",
        "live_nodes.json",
        "live_stats.json",
        "status.json",
    )
    for name in required:
        if not (public_dir / name).is_file():
            problems.append(f"missing file: {name}")
    if not (public_dir / "countries").is_dir():
        problems.append("missing directory: countries")
    if problems:
        return problems

    # metadata JSON files must stay credential-free
    metadata_files = [public_dir / name for name in ("live_nodes.json", "live_stats.json", "status.json", "feed_manifest.json")]
    metadata_files.extend(sorted((public_dir / "clients").glob("*manifest.json")) if (public_dir / "clients").is_dir() else [])
    metadata_files.extend(sorted((public_dir / "operators").glob("*/manifest.json")) if (public_dir / "operators").is_dir() else [])
    for path in metadata_files:
        if not path.is_file():
            continue
        name = path.relative_to(public_dir).as_posix()
        text = path.read_text(encoding="utf-8")
        if _PROXY_URI_SCHEME_RE.search(text):
            problems.append(f"{name} contains a proxy URI")
        if _UUID_RE.search(text):
            problems.append(f"{name} contains a UUID")
        if '"password"' in text or '"uuid"' in text or '"token"' in text:
            problems.append(f"{name} contains a sensitive JSON key")

    # base64 must match subscription.txt exactly
    try:
        subscription = (public_dir / "subscription.txt").read_text(encoding="utf-8")
    except OSError as exc:
        problems.append(f"subscription.txt unreadable: {exc}")
        return problems
    try:
        encoded = (public_dir / "subscription_base64.txt").read_text(
            encoding="ascii"
        ).strip()
        if base64.b64decode(encoded, validate=True).decode("utf-8") != subscription:
            problems.append("subscription_base64.txt does not match subscription.txt")
    except (ValueError, UnicodeDecodeError):
        problems.append("subscription_base64.txt is not valid base64")

    # Multi-core layer: the main subscription IS the universal feed.
    universal_feed = public_dir / "clients" / "universal.txt"
    if universal_feed.is_file():
        if universal_feed.read_bytes() != (public_dir / "subscription.txt").read_bytes():
            problems.append("clients/universal.txt does not match subscription.txt")
        universal_b64 = public_dir / "clients" / "universal_base64.txt"
        if universal_b64.is_file():
            try:
                decoded = base64.b64decode(
                    universal_b64.read_text(encoding="ascii").strip(), validate=True
                ).decode("utf-8")
                if decoded != subscription:
                    problems.append("clients/universal_base64.txt does not match subscription.txt")
            except (ValueError, UnicodeDecodeError):
                problems.append("clients/universal_base64.txt is not valid base64")

    # Client/network feed base64 files must match their txt files.
    for sub_name in ("clients", "networks", "profiles", "operators"):
        sub_dir = public_dir / sub_name
        if not sub_dir.is_dir():
            continue
        for txt_file in sorted(sub_dir.rglob("*.txt")):
            if txt_file.name.endswith(FEED_B64_SUFFIX):
                continue
            b64_file = txt_file.with_name(txt_file.stem + FEED_B64_SUFFIX)
            if not b64_file.is_file():
                continue
            try:
                decoded = base64.b64decode(
                    b64_file.read_text(encoding="ascii").strip(), validate=True
                ).decode("utf-8")
                if decoded != txt_file.read_text(encoding="utf-8"):
                    problems.append(
                        f"{sub_name}/{b64_file.name} does not match {txt_file.name}"
                    )
            except (ValueError, UnicodeDecodeError):
                problems.append(f"{sub_name}/{b64_file.name} is not valid base64")
        yaml_file = sub_dir / "mihomo.yaml"
        if yaml_file.is_file():
            problems.extend(_verify_mihomo_yaml(sub_name, yaml_file))
        if sub_name == "operators":
            for operator_yaml in sorted(sub_dir.glob("*/mihomo.yaml")):
                problems.extend(_verify_mihomo_yaml(operator_yaml.parent.name, operator_yaml))

    try:
        nodes = json.loads((public_dir / "live_nodes.json").read_text(encoding="utf-8"))
        stats = json.loads((public_dir / "live_stats.json").read_text(encoding="utf-8"))
        status = json.loads((public_dir / "status.json").read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        problems.append(f"metadata JSON unreadable: {exc}")
        return problems

    if not isinstance(nodes, list) or not nodes:
        problems.append("live_nodes.json must be a non-empty JSON array")
    else:
        for index, node in enumerate(nodes):
            if not isinstance(node, dict) or node.get("status") != "live":
                problems.append(f"live_nodes.json entry {index} is not a LIVE node")
        # The main subscription is the universal feed when the multi-core
        # layer ran; otherwise (legacy outputs) live_total.
        subscription_lines = [
            line for line in subscription.splitlines() if line.strip()
        ]
        expected = (
            stats["universal_count"]
            if stats.get("universal_count") is not None
            else stats.get("live_total")
        )
        if expected is not None and len(subscription_lines) != expected:
            problems.append("subscription.txt line count does not match expected feed size")

    if stats.get("publish_status") != "published":
        problems.append("live_stats.json publish_status must be 'published'")

    best_lines = [
        line for line in (public_dir / "best.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    live_selected = stats.get("live_selected")
    if not isinstance(live_selected, int) or live_selected != len(best_lines):
        problems.append("best.txt line count does not match live_selected")
    if isinstance(status.get("live_nodes"), int) and status["live_nodes"] != live_selected:
        problems.append("status.json live_nodes does not match live_selected")
    for key in _STATUS_REQUIRED_KEYS:
        if key not in status:
            problems.append(f"status.json missing key: {key}")

    country_files = {p.stem for p in (public_dir / "countries").glob("*.txt")}
    by_country = stats.get("count_by_country")
    if isinstance(by_country, dict):
        if country_files != set(by_country):
            problems.append("countries/ does not match live_stats.json count_by_country")
    else:
        problems.append("live_stats.json count_by_country must be a mapping")

    return problems


def _verify_mihomo_yaml(sub_name: str, yaml_file: Path) -> list[str]:
    """Validate a staged/published Mihomo YAML (parse + unique names).

    The YAML is a *subscription config*: like ``subscription.txt`` it
    legitimately carries proxy credentials, so the metadata-JSON secret
    scan deliberately does NOT apply here. What IS checked: parseability,
    a non-empty proxies list and unique proxy names (spec item 13).
    """
    problems: list[str] = []
    try:
        payload = yaml.safe_load(yaml_file.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        return [f"{sub_name}/mihomo.yaml is not valid YAML: {type(exc).__name__}"]
    if not isinstance(payload, dict):
        return [f"{sub_name}/mihomo.yaml must be a mapping"]
    proxies = payload.get("proxies")
    if not isinstance(proxies, list) or not proxies:
        return [f"{sub_name}/mihomo.yaml must contain a non-empty proxies list"]
    names = [str(proxy.get("name")) for proxy in proxies if isinstance(proxy, dict)]
    if len(names) != len(proxies):
        problems.append(f"{sub_name}/mihomo.yaml has proxy entries without names")
    if len(names) != len(set(names)):
        problems.append(f"{sub_name}/mihomo.yaml has duplicate proxy names")
    return problems


# -- orchestration ----------------------------------------------------------------------


def run_publish(options: PublishOptions) -> PublishResult:
    """Recover -> plan -> stage -> verify -> promote -> decide."""
    recovery_actions = recover_publish_transaction(options.public_dir, options.staging_dir)
    for action in recovery_actions:
        logger.warning("publish recovery: %s", action)
    result, stats = plan_publish(options)

    baseline_cache = dict(options.security_cache_baseline or {})

    if result.decision != DECISION_PUBLISHED:
        # Guarded skip: public/ untouched; history/security caches may
        # still be committed (they are bounded and credential-free).
        history_changed = meaningful_history_changes(
            options.history_baseline_text, _read_text(options.history_path)
        )
        cache_changed = security_cache_changed(
            baseline_cache, snapshot_security_cache(options.security_cache_dir)
        )
        result.commit_recommended = history_changed or cache_changed
        if history_changed:
            result.commit_message = MSG_COMMIT_HISTORY
        elif cache_changed:
            result.commit_message = MSG_COMMIT_SECURITY_CACHE
        else:
            result.commit_message = None
        if history_changed:
            result.meaningful_changes.append("data/history.json")
        if cache_changed:
            result.meaningful_changes.append(SECURITY_CACHE_PREFIX)
        _write_decision(options.output_dir, result)
        return result

    old_snapshot = snapshot_dir(options.public_dir)
    result.staged_files = _stage_public(options, stats)
    new_snapshot = snapshot_dir(options.staging_dir)

    public_changes = meaningful_public_changes(old_snapshot, new_snapshot)
    history_changed = meaningful_history_changes(
        options.history_baseline_text, _read_text(options.history_path)
    )
    cache_changed = security_cache_changed(
        baseline_cache, snapshot_security_cache(options.security_cache_dir)
    )
    result.meaningful_changes = list(public_changes)
    if history_changed:
        result.meaningful_changes.append("data/history.json")
    if cache_changed:
        result.meaningful_changes.append(SECURITY_CACHE_PREFIX)

    promote_public(options.staging_dir, options.public_dir)

    result.commit_recommended = bool(public_changes or history_changed or cache_changed)
    if public_changes:
        result.commit_message = MSG_COMMIT_PUBLISH
    elif history_changed:
        result.commit_message = MSG_COMMIT_HISTORY
    elif cache_changed:
        result.commit_message = MSG_COMMIT_SECURITY_CACHE
    else:
        result.commit_message = None  # volatile-only run: no commit, ever

    _write_decision(options.output_dir, result)
    logger.info(
        "publish complete: %d live nodes (previous %s), commit_recommended=%s",
        result.live_count,
        result.previous_count,
        result.commit_recommended,
    )
    return result


def _read_text(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return None


def _write_decision(output_dir: Path, result: PublishResult) -> None:
    """Persist the credential-free decision for CI logging and artifacts."""
    try:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "decision": result.decision,
            "reasons": result.reasons,
            "live_count": result.live_count,
            "previous_count": result.previous_count,
            "commit_recommended": result.commit_recommended,
            "commit_message": result.commit_message,
            "meaningful_changes": result.meaningful_changes,
        }
        (output_dir / "publish_decision.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",newline="\n"
        )
    except OSError as exc:  # never fail a publish because of a log file
        logger.warning("cannot write publish_decision.json: %s", exc)


def resolve_history_baseline(history_path: Path | None, baseline_file: Path | None,
                             repo_root: Path | None = None) -> str | None:
    """Baseline text of the *committed* history for meaningful-diff.

    Resolution order (first hit wins):
    1. explicit snapshot file (the workflow snapshots ``data/history.json``
       before the pipeline runs),
    2. ``git show HEAD:<path>`` inside ``repo_root`` (read-only, no
       credentials, bounded to one call),
    3. ``None`` — no baseline known; the new history then counts as changed.
    """
    if baseline_file is not None and Path(baseline_file).is_file():
        return _read_text(baseline_file)
    if history_path is not None and repo_root is not None:
        import subprocess

        try:
            rel = Path(history_path).resolve().relative_to(Path(repo_root).resolve())
            completed = subprocess.run(
                ["git", "show", f"HEAD:{rel.as_posix()}"],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if completed.returncode == 0:
                return completed.stdout
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    return None
