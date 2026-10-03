from __future__ import annotations
import json
from pathlib import Path

import yaml

from auto_subscription_engine.core.feeds import FeedOptions, run_feed_stage
from auto_subscription_engine.core.hardening.publication import PublishOptions, _stage_public, verify_public_dir
from test_feed_engine import _build_output


def test_main_workflow_gates_feed_stage_between_scoring_and_publish():
    path = Path('.github/workflows/build-subscription.yml')
    text = path.read_text(encoding='utf-8')
    parsed = yaml.safe_load(text)
    assert 'build' in parsed['jobs']
    score_at = text.index('verify-score --output-dir output')
    feed_at = text.index('feed-build')
    verify_at = text.index('verify-feed --output-dir output')
    publish_at = text.index('python -m auto_subscription_engine publish')
    assert score_at < feed_at < verify_at < publish_at
    assert 'output/profiles/' in text
    assert 'output/operators/' in text
    assert 'output/feed_manifest.json' in text


def test_publisher_stages_stage10_artifacts(tmp_path: Path):
    output = _build_output(tmp_path)
    run_feed_stage(FeedOptions(output_dir=output, config_path=Path('config/feeds.yaml')))
    stats = json.loads((output / 'live_stats.json').read_text(encoding='utf-8'))
    stats.update({
        'live_selected': 2,
        'count_by_country': {},
        'effective_config': {'core_version': 'test'},
    })
    options = PublishOptions(
        output_dir=output,
        public_dir=tmp_path / 'public',
        staging_dir=tmp_path / 'staging',
        engine_commit='stage10-test',
        run_started_at='2026-10-03T00:00:00+00:00',
    )
    staged = _stage_public(options, stats)
    assert 'profiles/recommended.txt' in staged
    assert 'operators/mci/manifest.json' in staged
    assert 'feed_manifest.json' in staged
    assert (options.staging_dir / 'operators/mci/v2rayng.txt').is_file()
    assert not (options.staging_dir / 'operators/irancell/v2rayng.txt').exists()
    assert verify_public_dir(options.staging_dir) == []
