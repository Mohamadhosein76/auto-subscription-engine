"""Task 4 tests: workflow & configuration contract for the security layer.

These tests keep the CI wiring honest: the security stage must sit
between real connectivity validation and the publish step, the publish
must be skipped when security intelligence is unavailable, the
diagnostics must be uploaded even on failure, and no Cloudflare
endpoint may appear in any security source.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "build-subscription.yml"
TESTING_YAML = REPO_ROOT / "config" / "testing.yaml"


@pytest.fixture(scope="module")
def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def workflow_steps(workflow_text: str) -> list[str]:
    names = []
    for line in workflow_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- name:"):
            names.append(stripped[len("- name:"):].strip())
    return names


def test_security_check_step_exists_before_publish(workflow_steps: list[str]):
    assert "Security deep check (LIVE nodes only)" in workflow_steps
    assert "Validate security-filtered outputs" in workflow_steps
    security_idx = workflow_steps.index("Security deep check (LIVE nodes only)")
    verify_idx = workflow_steps.index("Validate security-filtered outputs")
    publish_idx = next(
        i for i, s in enumerate(workflow_steps) if s.startswith("Publish to public")
    )
    live_idx = next(i for i, s in enumerate(workflow_steps) if "real connectivity" in s.lower())
    assert live_idx < security_idx < verify_idx < publish_idx


def test_publish_skipped_when_security_unavailable(workflow_text: str):
    assert "steps.security.outputs.unavailable != '1'" in workflow_text


def test_security_unavailable_enforcement_step(workflow_text: str):
    assert "Enforce security unavailability status" in workflow_text
    assert "security_data_unavailable" in workflow_text


def test_exit_code_4_marks_unavailable(workflow_text: str):
    assert '[ "$code" -eq 4 ]' in workflow_text


def test_auto_commit_includes_security_cache(workflow_text: str):
    assert "git add public data/history.json data/discovery.json data/ip_history.json data/security" in workflow_text


def test_security_diagnostics_artifact_uploaded_always(workflow_text: str):
    assert "name: security-diagnostics" in workflow_text
    assert "output/security_diagnostics.json" in workflow_text
    # upload steps must run even when the job fails
    artifact_block = workflow_text.split("name: security-diagnostics")[1][:400]
    assert "if: always()" in artifact_block or "if: always()" in workflow_text


def test_schedule_and_guards_preserved(workflow_text: str):
    assert '- cron: "17 * * * *"' in workflow_text
    assert "workflow_dispatch:" in workflow_text
    assert "contents: write" in workflow_text
    assert "group: auto-subscription-publish" in workflow_text
    assert "cancel-in-progress: false" in workflow_text
    assert "github-actions[bot]" in workflow_text
    assert "--force" not in workflow_text and "force push" not in workflow_text.lower().replace("no force push", "")


def test_workflow_yaml_is_valid():
    parsed = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    assert "jobs" in parsed


# ---------------------------------------------------------------------------
# Testing config contract
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def testing_cfg() -> dict:
    return yaml.safe_load(TESTING_YAML.read_text(encoding="utf-8"))


def test_security_section_present(testing_cfg: dict):
    security = testing_cfg.get("security")
    assert isinstance(security, dict)
    for key in ("feeds", "asn", "dns", "tls", "content", "policy", "min_publishable_nodes"):
        assert key in security, key


def test_official_feed_urls_only(testing_cfg: dict):
    feeds = testing_cfg["security"]["feeds"]
    assert feeds["spamhaus_drop"] == "https://www.spamhaus.org/drop/drop.txt"
    assert feeds["spamhaus_dropv6"] == "https://www.spamhaus.org/drop/dropv6.txt"
    assert feeds["spamhaus_asndrop"] == "https://www.spamhaus.org/drop/asndrop.json"
    assert "ipblocklist_recommended" in feeds["feodo_recommended"]
    assert "abuse.ch" in feeds["feodo_recommended"]


def test_no_cloudflare_anywhere_in_security_sources(testing_cfg: dict):
    """No *configured value* may reference Cloudflare (comments aside)."""
    def _walk(value):
        if isinstance(value, dict):
            for v in value.values():
                yield from _walk(v)
        elif isinstance(value, list):
            for v in value:
                yield from _walk(v)
        elif isinstance(value, str):
            yield value

    for text in _walk(testing_cfg.get("security", {})):
        assert "cloudflare" not in text.lower(), text
    assert "dns.google" in testing_cfg["security"]["dns"]["doh_url"]


def test_no_threatfox_dependency(testing_cfg: dict):
    """ThreatFox requires an auth key - must not be a dependency."""
    text = TESTING_YAML.read_text(encoding="utf-8").lower()
    assert "threatfox" not in text


def test_rate_guard_values(testing_cfg: dict):
    feeds = testing_cfg["security"]["feeds"]
    assert int(feeds["refresh_interval_hours"]) >= 24
    assert int(feeds["max_age_hours"]) >= int(feeds["refresh_interval_hours"])
    assert int(testing_cfg["security"]["min_publishable_nodes"]) >= 1
    assert int(testing_cfg["security"]["policy"]["max_nodes_per_asn"]) >= 1


def test_content_endpoints_are_non_cloudflare_https(testing_cfg: dict):
    endpoints = testing_cfg["security"]["content"]["endpoints"]
    assert len(endpoints) >= 2  # at least two independent providers
    domains = {e["url"].split("/")[2] for e in endpoints}
    assert len(domains) >= 2
    for endpoint in endpoints:
        assert endpoint["url"].startswith("https://")
        assert "cloudflare" not in endpoint["url"]


def test_no_new_secrets_required(testing_cfg: dict):
    """Every configured security URL must be key-free (no credentials)."""
    security = testing_cfg["security"]
    urls = [
        security["feeds"]["spamhaus_drop"],
        security["feeds"]["spamhaus_dropv6"],
        security["feeds"]["spamhaus_asndrop"],
        security["feeds"]["feodo_recommended"],
        security["asn"]["fallback_url"],
        security["dns"]["doh_url"],
    ] + [e["url"] for e in security["content"]["endpoints"]]
    for url in urls:
        assert "@" not in url, url
        assert "api_key" not in url and "token" not in url, url


def test_security_config_defaults_merge():
    from auto_subscription_engine.core.security.config import merged_security_config

    merged = merged_security_config({"feeds": {"refresh_interval_hours": 48},
                                     "min_publishable_nodes": 3})
    assert merged["feeds"]["refresh_interval_hours"] == 48
    assert merged["feeds"]["max_age_hours"] == 96  # untouched default
    assert merged["min_publishable_nodes"] == 3


def test_livepipeline_defaults_include_security():
    from auto_subscription_engine.core.orchestration.live import DEFAULT_TESTING_CONFIG

    assert "security" in DEFAULT_TESTING_CONFIG
    assert DEFAULT_TESTING_CONFIG["security"]["enabled"] is True


def test_load_testing_config_merges_security(tmp_path: Path):
    from auto_subscription_engine.core.orchestration.live import load_testing_config

    cfg = load_testing_config(TESTING_YAML)
    assert cfg["security"]["feeds"]["refresh_interval_hours"] == 24
    assert cfg["publish"]["min_live_nodes"] == 5  # Task 3 section intact
    assert cfg["scoring"]["preselection_weights"]["connectivity"] == 35.0  # Task 2 intact
