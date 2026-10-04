"""Production release gate and health report.

The gate is intentionally read-only.  It checks the promoted public tree,
persistent state integrity, repository hygiene and generated Stage 9/10
artifacts before an automated commit/push is allowed.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

import yaml

from .publication import verify_public_dir
from .state import StateCorruptionError, load_json_state
from ..feeds import verify_feed_outputs
from ..scoring import verify_scoring_outputs

_PROXY_RE = re.compile(r"\b(?:vless|vmess|trojan|hysteria2|hy2|tuic|ss)://", re.I)
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_SENSITIVE_KEY_RE = re.compile(r'"(?:password|uuid|token|secret|identity)"\s*:', re.I)


@dataclass(frozen=True)
class GateCheck:
    name: str
    passed: bool
    detail: str


@dataclass
class ReleaseGateReport:
    status: str
    checks: list[GateCheck]

    @property
    def passed(self) -> bool:
        return self.status == "ok" and all(item.passed for item in self.checks)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "passed": self.passed,
            "checks": [asdict(item) for item in self.checks],
        }


def _check(name: str, problems: Iterable[str]) -> GateCheck:
    issues = [str(item) for item in problems if str(item).strip()]
    if issues:
        return GateCheck(name=name, passed=False, detail="; ".join(issues[:20]))
    return GateCheck(name=name, passed=True, detail="ok")


def _yaml_problems(repo_root: Path) -> list[str]:
    problems: list[str] = []
    for path in sorted((repo_root / "config").glob("*.yaml")):
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{path.relative_to(repo_root)}: {type(exc).__name__}")
            continue
        if payload is None:
            problems.append(f"{path.relative_to(repo_root)}: empty YAML")
    for path in sorted((repo_root / ".github" / "workflows").glob("*.yml")):
        try:
            yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{path.relative_to(repo_root)}: {type(exc).__name__}")
    return problems


def _state_problems(repo_root: Path, max_bytes: int) -> list[str]:
    problems: list[str] = []
    state_paths = (
        Path("data/history.json"),
        Path("data/discovery.json"),
        Path("data/ip_history.json"),
        Path("data/operator_probes.json"),
    )
    for relative in state_paths:
        path = repo_root / relative
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > max_bytes:
                problems.append(f"{relative}: exceeds {max_bytes} bytes")
            payload = load_json_state(path, recover_backup=False)
            if not isinstance(payload, dict):
                problems.append(f"{relative}: JSON root must be an object")
                continue
            text = path.read_text(encoding="utf-8")
            if _PROXY_RE.search(text) or _UUID_RE.search(text) or _SENSITIVE_KEY_RE.search(text):
                problems.append(f"{relative}: sensitive proxy material detected")
        except (OSError, UnicodeDecodeError, StateCorruptionError) as exc:
            problems.append(f"{relative}: {exc}")
    return problems


def _transaction_problems(repo_root: Path, public_dir: Path) -> list[str]:
    problems: list[str] = []
    staging = public_dir.with_name(public_dir.name + ".staging")
    if staging.exists():
        problems.append(f"stale staging directory exists: {staging.name}")
    backups = sorted(public_dir.parent.glob(f".{public_dir.name}.old-*"))
    if backups:
        problems.append(f"stale publish backups exist: {len(backups)}")
    for path in sorted(repo_root.rglob("*.tmp")):
        if any(part in {".git", ".pytest_cache"} for part in path.parts):
            continue
        problems.append(f"stale temp file: {path.relative_to(repo_root)}")
        if len(problems) >= 20:
            break
    return problems


def _tracked_artifact_problems(repo_root: Path) -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"git ls-files unavailable: {exc}"]
    if proc.returncode != 0:
        return ["git ls-files failed"]
    bad: list[str] = []
    for line in proc.stdout.splitlines():
        parts = Path(line).parts
        if (
            "__pycache__" in parts
            or ".pytest_cache" in parts
            or any(part.endswith(".egg-info") for part in parts)
            or line.startswith(".core-bin/")
            or line.endswith(".bak")
        ):
            bad.append(line)
    return [f"tracked generated artifact: {item}" for item in bad]


def run_release_gate(
    *,
    repo_root: Path,
    output_dir: Path,
    public_dir: Path,
    max_state_bytes: int = 64 * 1024 * 1024,
) -> ReleaseGateReport:
    repo_root = Path(repo_root).resolve()
    output_dir = (repo_root / output_dir).resolve() if not Path(output_dir).is_absolute() else Path(output_dir)
    public_dir = (repo_root / public_dir).resolve() if not Path(public_dir).is_absolute() else Path(public_dir)

    checks: list[GateCheck] = []
    checks.append(_check("public_tree", verify_public_dir(public_dir)))
    if (output_dir / "scorecards.json").is_file():
        checks.append(_check("scorecards", verify_scoring_outputs(output_dir)))
    else:
        checks.append(GateCheck("scorecards", False, "scorecards.json missing"))
    if (output_dir / "feed_manifest.json").is_file():
        checks.append(_check("feeds", verify_feed_outputs(output_dir)))
    else:
        checks.append(GateCheck("feeds", False, "feed_manifest.json missing"))
    checks.append(_check("yaml", _yaml_problems(repo_root)))
    checks.append(_check("persistent_state", _state_problems(repo_root, max_state_bytes)))
    checks.append(_check("publish_transaction", _transaction_problems(repo_root, public_dir)))
    checks.append(_check("repository_hygiene", _tracked_artifact_problems(repo_root)))

    status = "ok" if all(item.passed for item in checks) else "failed"
    return ReleaseGateReport(status=status, checks=checks)


def write_release_gate_report(path: Path, report: ReleaseGateReport) -> None:
    # Output is credential-free by construction.  It is a run artifact, not
    # persistent state, so a normal write is sufficient.
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
