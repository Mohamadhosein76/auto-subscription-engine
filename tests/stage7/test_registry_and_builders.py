from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from auto_subscription_engine.core.clients.builders.mihomo import build_mihomo_proxy
from auto_subscription_engine.core.clients.builders.singbox import UnsupportedNodeError, build_outbound
from auto_subscription_engine.core.clients.compatibility.audit import node_features
from auto_subscription_engine.core.clients.compatibility.matrix import capabilities_for
from auto_subscription_engine.core.clients.registry import CLIENTS, PLANNED_CLIENTS, client_spec
from auto_subscription_engine.core.clients.runtime import CoreRuntimeManager
from auto_subscription_engine.core.models import ParsedConfig


def cfg(protocol: str, *, transport: str = "tcp", params: dict[str, str] | None = None) -> ParsedConfig:
    base = dict(params or {})
    if transport:
        base.setdefault("type", transport)
    identity = "11111111-2222-3333-4444-555555555555"
    if protocol == "ss":
        identity = "aes-256-gcm:secret"
    if protocol == "hysteria2":
        identity = "hy-secret"
    return ParsedConfig(
        protocol=protocol,
        host="edge.example.com",
        port=443,
        identity=identity,
        params=base,
        original_uri=f"{protocol}://redacted",
        fingerprint=f"fp-{protocol}-{transport}",
    )


def test_registry_maps_only_runtime_verified_clients() -> None:
    assert CLIENTS["v2rayng"].core == "xray"
    assert CLIENTS["hiddify"].core == "hiddify"
    assert CLIENTS["nekobox"].core == "singbox"
    assert CLIENTS["singbox"].format == "singbox-json"
    assert CLIENTS["mihomo"].format == "mihomo-yaml"
    for planned in PLANNED_CLIENTS:
        with pytest.raises(KeyError):
            client_spec(planned)


def test_xhttp_is_client_core_specific_not_globally_refused() -> None:
    node = cfg("vless", transport="xhttp", params={"security": "tls", "sni": "edge.example.com", "path": "/x"})
    caps = capabilities_for(node_features(node))
    assert caps["xray"].supported is True
    assert caps["mihomo"].supported is True
    assert caps["singbox"].supported is False
    assert caps["hiddify"].supported is False
    with pytest.raises(UnsupportedNodeError):
        build_outbound(node)
    mihomo = build_mihomo_proxy(node)
    assert mihomo["network"] == "xhttp"
    assert mihomo["xhttp-opts"]["path"] == "/x"


def test_tuic_supported_by_singbox_hiddify_mihomo_not_xray(tmp_path: Path) -> None:
    node = cfg(
        "tuic",
        transport="quic",
        params={
            "password": "tuic-pass",
            "sni": "tuic.example.com",
            "congestion_control": "bbr",
            "udp_relay_mode": "native",
        },
    )
    caps = capabilities_for(node_features(node))
    assert caps["singbox"].supported
    assert caps["hiddify"].supported
    assert caps["mihomo"].supported
    assert not caps["xray"].supported

    outbound = build_outbound(node)
    assert outbound["type"] == "tuic"
    assert outbound["password"] == "tuic-pass"
    assert outbound["congestion_control"] == "bbr"

    mihomo = build_mihomo_proxy(node)
    assert mihomo["type"] == "tuic"
    assert mihomo["password"] == "tuic-pass"
    assert mihomo["congestion-controller"] == "bbr"

    paths = {}
    for core in ("singbox", "xray", "hiddify", "mihomo"):
        binary = tmp_path / core
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)
        paths[core] = binary
    manager = CoreRuntimeManager(paths)
    assert manager.candidate_cores(node) == ["singbox", "hiddify", "mihomo"]


def test_runtime_manager_routes_xhttp_to_xray_or_mihomo(tmp_path: Path) -> None:
    node = cfg("vless", transport="xhttp", params={"security": "tls", "sni": "edge.example.com"})
    paths = {}
    for core in ("singbox", "xray", "hiddify", "mihomo"):
        binary = tmp_path / core
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        binary.chmod(0o755)
        paths[core] = binary
    manager = CoreRuntimeManager(paths)
    assert manager.candidate_cores(node) == ["xray", "mihomo"]


def test_stage5_runtime_can_prove_xhttp_with_xray_without_trying_singbox(monkeypatch) -> None:
    from auto_subscription_engine.core.verification.models import ApplicationProbeResult
    from auto_subscription_engine.core.verification.policy import VerificationPolicy
    from auto_subscription_engine.core.verification.runtime import CoreRuntimeRunner
    import auto_subscription_engine.core.verification.runtime as verification_runtime

    node = cfg("vless", transport="xhttp", params={"security": "tls", "sni": "edge.example.com", "path": "/x"})
    policy = VerificationPolicy.from_mapping({
        "repetitions": 1,
        "min_success_ratio": 1.0,
        "min_success_count": 1,
        "targets": [{"url": "https://example.test/", "expect_status": [200]}],
    })
    runner = CoreRuntimeRunner(core_paths={}, policy=policy)

    class Session:
        core = "xray"
        port = 18888
        def close(self):
            return None

    class Manager:
        def candidate_cores(self, config, preferred=None):
            return ["xray", "mihomo"]
        def open(self, core, config, server_override=None):
            assert core == "xray"
            return Session()
        def cleanup(self):
            return None

    runner.manager = Manager()

    def fake_probe(host, port, target, *, timeout, round_index, max_body_bytes):
        return ApplicationProbeResult(
            url=target.url,
            required=True,
            round_index=round_index,
            ok=True,
            status=200,
            latency_ms=12.0,
        )

    monkeypatch.setattr(verification_runtime, "fetch_through_proxy", fake_probe)
    result = runner.probe_node(node)
    assert result.passed is True
    assert result.runtime_core == "xray"
    assert result.attempted_cores == ["xray"]
