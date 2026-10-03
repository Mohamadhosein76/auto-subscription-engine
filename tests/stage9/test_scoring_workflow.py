from pathlib import Path

import yaml


def test_build_workflow_runs_scoring_after_compat_before_publish():
    root = Path(__file__).resolve().parents[2]
    path = root / ".github/workflows/build-subscription.yml"
    text = path.read_text(encoding="utf-8")
    yaml.safe_load(text)
    compat = text.index("python -m auto_subscription_engine verify-compat")
    score = text.index("python -m auto_subscription_engine score-check")
    verify = text.index("python -m auto_subscription_engine verify-score")
    publish = text.index("python -m auto_subscription_engine publish")
    assert compat < score < verify < publish
    assert "output/scorecards.json" in text


def test_scoring_sources_are_central_only():
    root = Path(__file__).resolve().parents[2]
    assert (root / "src/auto_subscription_engine/core/scoring").is_dir()
    assert not (root / "src/auto_subscription_engine/scoring.py").exists()
    assert not (root / "src/auto_subscription_engine/core/clients/compatibility/score.py").exists()
