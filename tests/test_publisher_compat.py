"""Multi-core publisher tests: client/network feeds + universal guard.

Covers the three publisher-side guarantees of the Universal Client &
Network Compatibility layer (all offline, fabricated post-compat outputs):

1. previous-good preservation PER client/network feed — a feed that
   comes back EMPTY in this run (its core failed validation, or every
   node failed the runtime test) never replaces the previous non-empty
   feed file; the preserved file's base64 is regenerated from the final
   bytes so the published pair always matches;
2. universal guard — a run whose ``universal_count`` is below
   ``min_universal_nodes`` must never replace the previous public tree
   (the main subscription IS the universal feed after the compat stage);
3. client-specific empty/failure protection — with NO previous good
   file, an empty feed is omitted entirely (an empty file is never
   published), and a Mihomo YAML that comes back without proxies is
   treated exactly like an empty text feed.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import yaml

from auto_subscription_engine.core.hardening.publication import (
    DECISION_PUBLISHED,
    DECISION_SKIPPED_MIN_UNIVERSAL,
    PublishOptions,
    run_publish,
    snapshot_dir,
)

FAKE_URIS = [
    f"vless://fake-identity-{i}@node-{i}.example:443?security=tls#fake-{i}"
    for i in range(1, 7)
]


def _write_uri_feed(path: Path, uris: list[str]) -> None:
    body = "\n".join(uris) + ("\n" if uris else "")
    path.write_text(body, encoding="utf-8", newline="\n")
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    path.with_name(path.stem + "_base64.txt").write_text(
        encoded + "\n", encoding="ascii"
    )


def _write_mihomo_yaml(path: Path, uris: list[str]) -> None:
    proxies = [
        {"name": f"ase-proxy-{i}", "type": "vless", "server": f"node-{i}.example",
         "port": 443, "uuid": f"fake-identity-{i}", "tls": True}
        for i, _uri in enumerate(uris, start=1)
    ]
    payload = {
        "port": 7890,
        "socks-port": 7891,
        "mode": "rule",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": [p["name"] for p in proxies]}
        ],
        "rules": ["MATCH,PROXY"],
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def build_output(
    root: Path,
    *,
    universal: list[str] | None = None,
    v2rayng: list[str] | None = None,
    hiddify: list[str] | None = None,
    nekobox: list[str] | None = None,
    mihomo_uris: list[str] | None = None,
    mobile_safe: list[str] | None = None,
) -> None:
    """Fabricate a valid post-compat output directory (no network).

    Mirrors the real contract of the compatibility stage:
    ``live_subscription.txt`` IS the universal feed and ``live_stats.json``
    carries ``universal_count``.
    """
    out = Path(root)
    (out / "countries").mkdir(parents=True, exist_ok=True)
    universal = FAKE_URIS[:4] if universal is None else universal

    body = "\n".join(universal) + ("\n" if universal else "")
    (out / "live_subscription.txt").write_text(body, encoding="utf-8", newline="\n")
    (out / "live_subscription_base64.txt").write_text(
        base64.b64encode(body.encode("utf-8")).decode("ascii") + "\n",
        encoding="ascii",
    )
    (out / "best.txt").write_text("\n".join(FAKE_URIS) + "\n", encoding="utf-8", newline="\n")

    nodes = [
        {
            "safe_id": f"node_{i:08x}",
            "protocol": "vless",
            "status": "live",
            "selected": True,
            "country_code": "DE",
            "country_name": "Germany",
            "resolved_ip": "203.0.113.1",
            "tcp_latency_ms": 20.0 + i,
            "proxy_latency_ms": 300.0 + i,
            "success_ratio": 1.0,
            "score": 70 + i % 10,
        }
        for i, _uri in enumerate(FAKE_URIS)
    ]
    (out / "live_nodes.json").write_text(json.dumps(nodes, indent=2) + "\n", encoding="utf-8")

    stats = {
        "generated_at": "2026-09-30T10:00:00+00:00",
        "mode": "fetch",
        "sources_total": 3,
        "sources_success": 3,
        "sources_failed": 0,
        "configs_received": 100,
        "final_configs": 90,
        "candidates_sampled": 80,
        "tcp_tested": 80,
        "tcp_passed": 40,
        "tcp_failure_reasons": {"timeout": 40},
        "proxy_candidates": 20,
        "proxy_tested": 20,
        "proxy_not_tested": 0,
        "proxy_live": len(FAKE_URIS),
        "proxy_failure_reasons": {},
        "live_total": len(FAKE_URIS),
        "live_selected": len(FAKE_URIS),
        "median_tcp_latency_ms": 25.0,
        "median_proxy_latency_ms": 310.0,
        "countries_discovered": 1,
        "count_by_country": {"DE": len(FAKE_URIS)},
        "count_by_protocol_live": {"vless": len(FAKE_URIS)},
        "runtime_seconds": 42.0,
        "status": "ok",
        "history_entries": 0,
        "universal_count": len(universal),
        "effective_config": {"core_version": "1.14.2"},
    }
    (out / "live_stats.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    (out / "countries" / "DE.txt").write_text(
        "\n".join(FAKE_URIS) + "\n", encoding="utf-8"
    )

    clients = out / "clients"
    networks = out / "networks"
    clients.mkdir(exist_ok=True)
    networks.mkdir(exist_ok=True)
    _write_uri_feed(clients / "universal.txt", universal)
    _write_uri_feed(clients / "v2rayng.txt", FAKE_URIS[:5] if v2rayng is None else v2rayng)
    _write_uri_feed(clients / "hiddify.txt", FAKE_URIS[:5] if hiddify is None else hiddify)
    _write_uri_feed(clients / "nekobox.txt", universal if nekobox is None else nekobox)
    _write_mihomo_yaml(clients / "mihomo.yaml", FAKE_URIS[:5] if mihomo_uris is None else mihomo_uris)
    _write_uri_feed(
        networks / "mobile-safe.txt", universal[:2] if mobile_safe is None else mobile_safe
    )
    _write_uri_feed(networks / "tcp.txt", FAKE_URIS[:5])
    _write_uri_feed(networks / "udp.txt", FAKE_URIS[5:])
    _write_uri_feed(networks / "ipv4.txt", FAKE_URIS)
    _write_uri_feed(networks / "ipv6.txt", [])
    _write_uri_feed(networks / "port443.txt", FAKE_URIS)


def make_options(tmp_path: Path, **overrides) -> PublishOptions:
    defaults = dict(
        output_dir=tmp_path / "output",
        public_dir=tmp_path / "public",
        staging_dir=tmp_path / "public.staging",
        history_path=tmp_path / "data" / "history.json",
        history_baseline_text=None,
        min_live_nodes=5,
        max_drop_ratio=0.80,
        engine_commit="abc1234",
        run_started_at="2026-09-30T11:00:00+00:00",
    )
    defaults.update(overrides)
    return PublishOptions(**defaults)


def _published_bytes(public_dir: Path, rel: str) -> bytes:
    return (Path(public_dir) / rel).read_bytes()


# ---------------------------------------------------------------------------
# 1. previous-good preservation PER client/network feed
# ---------------------------------------------------------------------------


def test_previous_good_client_feed_preserved_when_new_run_empty(tmp_path):
    output = tmp_path / "output"
    build_output(output)
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_PUBLISHED
    previous_v2rayng = _published_bytes(tmp_path / "public", "clients/v2rayng.txt")
    previous_b64 = _published_bytes(tmp_path / "public", "clients/v2rayng_base64.txt")
    assert previous_v2rayng.strip()

    # Next run: the xray core could not be verified -> the compat stage
    # writes an EMPTY v2rayng feed. Everything else stays healthy.
    build_output(output, v2rayng=[])
    result2 = run_publish(make_options(tmp_path))
    assert result2.decision == DECISION_PUBLISHED

    public = tmp_path / "public"
    # The empty feed did NOT replace the previous good file.
    assert _published_bytes(public, "clients/v2rayng.txt") == previous_v2rayng
    # The preserved pair stays consistent (base64 regenerated from final bytes).
    assert _published_bytes(public, "clients/v2rayng_base64.txt") == previous_b64
    assert base64.b64decode(
        _published_bytes(public, "clients/v2rayng_base64.txt").decode("ascii")
    ) == previous_v2rayng
    # A healthy feed IS refreshed normally.
    assert _published_bytes(public, "clients/hiddify.txt").strip()


def test_previous_good_network_feed_preserved_and_empty_yaml_kept(tmp_path):
    output = tmp_path / "output"
    build_output(output)
    run_publish(make_options(tmp_path))
    public = tmp_path / "public"
    previous_mobile = _published_bytes(public, "networks/mobile-safe.txt")
    previous_yaml = _published_bytes(public, "clients/mihomo.yaml")
    assert previous_mobile.strip() and previous_yaml.strip()

    # Every node failed the mobile heuristics and the mihomo core broke:
    # both feeds come back empty.
    build_output(output, mobile_safe=[], mihomo_uris=[])
    run_publish(make_options(tmp_path))

    assert _published_bytes(public, "networks/mobile-safe.txt") == previous_mobile
    assert _published_bytes(public, "clients/mihomo.yaml") == previous_yaml
    payload = yaml.safe_load(previous_yaml.decode("utf-8"))
    assert payload["proxies"]  # preserved YAML still carries proxies


# ---------------------------------------------------------------------------
# 2. universal guard
# ---------------------------------------------------------------------------


def test_universal_guard_skips_publish_and_preserves_public_tree(tmp_path):
    output = tmp_path / "output"
    build_output(output)
    run_publish(make_options(tmp_path))
    public = tmp_path / "public"
    before = snapshot_dir(public)
    assert before

    # Compat stage found zero universal nodes -> stats.universal_count = 0.
    build_output(output, universal=[])
    stats = json.loads((output / "live_stats.json").read_text(encoding="utf-8"))
    stats["universal_count"] = 0
    (output / "live_stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")

    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_SKIPPED_MIN_UNIVERSAL
    assert any("min_universal_nodes" in reason for reason in result.reasons)
    # Public tree untouched, byte for byte.
    assert snapshot_dir(public) == before
    # The decision is persisted for CI/artifacts.
    decision = json.loads((output / "publish_decision.json").read_text(encoding="utf-8"))
    assert decision["decision"] == DECISION_SKIPPED_MIN_UNIVERSAL


def test_universal_guard_threshold_is_configurable(tmp_path):
    output = tmp_path / "output"
    build_output(output)  # universal_count == 4
    # A strict threshold above the available universal nodes must skip.
    result = run_publish(make_options(tmp_path, min_universal_nodes=10))
    assert result.decision == DECISION_SKIPPED_MIN_UNIVERSAL
    assert not (tmp_path / "public").exists()  # nothing ever published

    # The same run publishes with the default threshold.
    result2 = run_publish(make_options(tmp_path, min_universal_nodes=1))
    assert result2.decision == DECISION_PUBLISHED


def test_published_main_subscription_is_the_universal_feed(tmp_path):
    output = tmp_path / "output"
    build_output(output, universal=FAKE_URIS[:2])
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_PUBLISHED
    public = tmp_path / "public"
    subscription = _published_bytes(public, "subscription.txt")
    assert subscription == _published_bytes(public, "clients/universal.txt")
    decoded = base64.b64decode(
        _published_bytes(public, "clients/universal_base64.txt").decode("ascii")
    )
    assert decoded == subscription
    assert len([ln for ln in subscription.decode("utf-8").splitlines() if ln.strip()]) == 2


# ---------------------------------------------------------------------------
# 3. client-specific empty/failure protection
# ---------------------------------------------------------------------------


def test_empty_feed_with_no_previous_good_is_omitted_never_published(tmp_path):
    output = tmp_path / "output"
    build_output(output, v2rayng=[], nekobox=[], universal=FAKE_URIS[:4])
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_PUBLISHED
    public = tmp_path / "public"
    # Empty feeds with no previous good file are omitted entirely.
    assert not (public / "clients" / "v2rayng.txt").exists()
    assert not (public / "clients" / "v2rayng_base64.txt").exists()
    assert not (public / "clients" / "nekobox.txt").exists()
    # Healthy feeds are still published.
    assert (public / "clients" / "hiddify.txt").is_file()
    assert (public / "clients" / "universal.txt").is_file()
    # An empty ipv6 network feed is omitted too.
    assert not (public / "networks" / "ipv6.txt").exists()
    assert (public / "networks" / "tcp.txt").is_file()


def test_client_feed_recovers_after_previous_failure(tmp_path):
    output = tmp_path / "output"
    build_output(output, v2rayng=[])
    run_publish(make_options(tmp_path))
    public = tmp_path / "public"
    assert not (public / "clients" / "v2rayng.txt").exists()

    # A later healthy run publishes the feed again.
    build_output(output, v2rayng=FAKE_URIS[:5])
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_PUBLISHED
    recovered = _published_bytes(public, "clients/v2rayng.txt")
    assert b"fake-1" in recovered
    assert base64.b64decode(
        _published_bytes(public, "clients/v2rayng_base64.txt").decode("ascii")
    ) == recovered


def test_first_publish_with_all_client_feeds_empty_still_publishes_core(tmp_path):
    """A broken compat stage must not take the main subscription down."""
    output = tmp_path / "output"
    build_output(
        output,
        universal=FAKE_URIS[:4],
        v2rayng=[],
        hiddify=[],
        nekobox=[],
        mihomo_uris=[],
        mobile_safe=[],
    )
    result = run_publish(make_options(tmp_path))
    assert result.decision == DECISION_PUBLISHED
    public = tmp_path / "public"
    # Main subscription (universal feed) is live even when every client
    # feed came back empty.
    assert _published_bytes(public, "subscription.txt").strip()
    assert not (public / "clients" / "v2rayng.txt").exists()
    assert not (public / "clients" / "mihomo.yaml").exists()
