from pathlib import Path


def test_old_scoring_sources_are_removed_and_imports_do_not_return():
    root = Path(__file__).resolve().parents[2]
    assert not (root / "src/auto_subscription_engine/scoring.py").exists()
    assert not (root / "src/auto_subscription_engine/core/clients/compatibility/score.py").exists()
    for path in (root / "src/auto_subscription_engine").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "from .scoring import" not in text
        assert "compatibility.score import" not in text
