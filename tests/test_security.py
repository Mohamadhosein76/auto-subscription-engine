"""Security tests: secrets never reach the repository or the logs."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

TOKEN_PATTERN = re.compile(r"github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}")

SCAN_DIRS = ("src", "config", "tests", ".github")
SCAN_FILES = ("README.md", "pyproject.toml", ".gitignore")


def _repo_files():
    for directory in SCAN_DIRS:
        for path in (REPO_ROOT / directory).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                yield path
    for name in SCAN_FILES:
        path = REPO_ROOT / name
        if path.is_file():
            yield path


def test_no_pat_or_token_pattern_anywhere_in_repo():
    for path in _repo_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        assert TOKEN_PATTERN.search(text) is None, f"token-like pattern in {path}"


def test_no_env_file_committed_in_repository():
    assert not (REPO_ROOT / ".env").exists()
    for path in REPO_ROOT.rglob(".env*"):
        assert path.name in (".env.example",), f"unexpected env file: {path}"


def test_gitignore_covers_required_secret_patterns():
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    lines = [line.strip() for line in gitignore.splitlines()]
    for required in (".env", ".env.*", "*.secret", ".cache/", ".core-bin/"):
        assert required in lines, f".gitignore is missing pattern: {required}"


def test_gitignore_task3_publishing_contract():
    # Task 3 contract: data/history.json and public/ are committed (persistent
    # history + published subscription); volatile outputs stay ignored.
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    lines = [line.strip() for line in gitignore.splitlines()]
    assert "data/history.json" not in lines, (
        "Task 3 commits data/history.json - it must not be gitignored"
    )
    assert "output/*" in lines, "volatile output/ files must stay gitignored"


def test_module_sources_never_embed_full_uri_examples_with_credentials():
    # URI-shaped literals in source must never carry real credential
    # userinfo; documentation placeholders like ``<base64(method:password@``
    # (angle-bracket notation) are allowed.
    uri_with_userinfo = re.compile(r"\w+://[^/\s@:\"'<]+:[^/\s@:\"'<]+@")
    for path in (REPO_ROOT / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in uri_with_userinfo.finditer(text):
            assert match.group(0).startswith(
                ("redact", "example", "test")
            ), f"credential-shaped URI literal in {path}: {match.group(0)[:40]}"


def test_redacted_failure_text_is_used_for_core_stderr():
    from auto_subscription_engine.core.utils.redaction import redact_stderr

    stderr = b"uuid=b831381d-6324-4d53-ad4f-8cda48b30811 password=real-secret-123456"
    cleaned = redact_stderr(stderr)
    assert "b831381d" not in cleaned
    assert "real-secret-123456" not in cleaned
