"""Tests for the reliability history store."""

from __future__ import annotations

import json

from auto_subscription_engine.core.scheduling import MAX_RECENT, ReliabilityHistory
from auto_subscription_engine.core.hardening.state import StateCorruptionError


def test_record_pass_updates_counters_and_rolling():
    history = ReliabilityHistory()
    entry = history.record("fp-a", passed=True, latency_ms=250.0)
    assert entry.checks_total == 1
    assert entry.checks_passed == 1
    assert entry.consecutive_successes == 1
    assert entry.consecutive_failures == 0
    assert entry.last_success is not None
    assert entry.last_failure is None
    assert entry.last_latency_ms == 250.0
    assert entry.rolling_success_rate == 1.0


def test_record_failure_breaks_streak():
    history = ReliabilityHistory()
    for _ in range(3):
        entry = history.record("fp-b", passed=True)
    entry = history.record("fp-b", passed=False)
    assert entry.consecutive_successes == 0
    assert entry.consecutive_failures == 1
    assert entry.last_failure is not None
    assert entry.last_latency_ms is None  # failures never set latency
    assert entry.rolling_success_rate == 0.75


def test_consecutive_failure_penalty_accumulates():
    history = ReliabilityHistory()
    for _ in range(4):
        entry = history.record("fp-c", passed=False)
    assert entry.consecutive_failures == 4
    assert entry.checks_passed == 0
    assert entry.rolling_success_rate == 0.0


def test_rolling_window_is_capped():
    history = ReliabilityHistory()
    for index in range(MAX_RECENT + 10):
        entry = history.record("fp-d", passed=(index % 2 == 0))
    assert len(entry.recent) == MAX_RECENT
    # Last 20 outcomes: pattern continues; whatever they are, rate in range.
    assert 0.0 <= entry.rolling_success_rate <= 1.0
    assert entry.recent[-1] == 0  # last index 29 is odd -> failure recorded


def test_save_and_load_roundtrip(tmp_path):
    path = tmp_path / "history.json"
    history = ReliabilityHistory()
    history.record("fp-e", passed=True, latency_ms=101.5)
    history.record("fp-e", passed=False)
    history.record("fp-f", passed=True)
    history.save(path)

    loaded = ReliabilityHistory.load(path)
    assert loaded.get("fp-e") is not None
    entry = loaded.get("fp-e")
    assert entry.checks_total == 2
    assert entry.checks_passed == 1
    assert entry.last_latency_ms == 101.5
    assert loaded.get("fp-f").checks_total == 1


def test_load_missing_file_starts_empty(tmp_path):
    history = ReliabilityHistory.load(tmp_path / "nope.json")
    assert history.entries == {}


def test_load_corrupt_file_fails_closed_without_backup(tmp_path):
    path = tmp_path / "history.json"
    path.write_text("{not valid json!!", encoding="utf-8")
    import pytest
    with pytest.raises(StateCorruptionError):
        ReliabilityHistory.load(path)


def test_load_corrupt_file_recovers_last_good_backup(tmp_path):
    path = tmp_path / "history.json"
    history = ReliabilityHistory()
    history.record("fp-stable", passed=True, timestamp="2026-09-29T09:00:00+00:00")
    history.save(path)
    history.record("fp-second", passed=True, timestamp="2026-09-29T10:00:00+00:00")
    history.save(path)  # creates history.json.bak with the first good state
    path.write_text("{truncated", encoding="utf-8")
    recovered = ReliabilityHistory.load(path)
    assert recovered.get("fp-stable") is not None
    assert recovered.get("fp-second") is None
    assert ReliabilityHistory.load(path).get("fp-stable") is not None


def test_load_skips_corrupt_entries(tmp_path):
    path = tmp_path / "history.json"
    payload = {
        "schema_version": 1,
        "entries": {
            "fp-good": {
                "fingerprint": "fp-good",
                "checks_total": 2,
                "checks_passed": 1,
                "recent": [1, 0],
                "rolling_success_rate": 0.5,
            },
            "fp-bad": {"checks_total": "not-a-number"},
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    history = ReliabilityHistory.load(path)
    assert "fp-good" in history.entries
    assert "fp-bad" not in history.entries


def test_save_none_is_noop(tmp_path):
    ReliabilityHistory().save(None)  # must not raise


def test_save_creates_parent_dirs(tmp_path):
    path = tmp_path / "deep" / "nested" / "history.json"
    history = ReliabilityHistory()
    history.record("fp-g", passed=True)
    history.save(path)
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    from auto_subscription_engine.core.scheduling import SCHEMA_VERSION
    assert data["schema_version"] == SCHEMA_VERSION
    assert "fp-g" in data["entries"]
