from __future__ import annotations

import os
import sys
import subprocess
from pathlib import Path

import pytest

from auto_subscription_engine.core.models import ParsedConfig
from auto_subscription_engine.core.verification import (
    CoreRuntimeRunner,
    EndpointPreflightResult,
    VerificationPolicy,
    VerificationTarget,
    fetch_through_proxy,
    run_runtime_stage,
)
import auto_subscription_engine.core.verification.runtime as runtime_module
import auto_subscription_engine.core.clients.runtime as client_runtime_module
from auto_subscription_engine.core.clients.builders import adapters as client_adapters

FIXTURES = Path(__file__).parents[1] / "fixtures" / "fake_cores"
SECRET_IDENTITY = "aes-256-gcm:super-secret-password-42"


def make_config(host="node.example", suffix="1"):
    item = ParsedConfig(protocol="ss", host=host, port=443, identity=SECRET_IDENTITY)
    item.fingerprint = f"fp-{suffix}"
    return item


@pytest.fixture()
def workdir_root(tmp_path):
    return tmp_path / "workdirs"


@pytest.fixture()
def ok_core(tmp_path):
    if os.name != "posix":
        source = FIXTURES / "fake_core_ok.py"
        target = tmp_path / "ok-core.cmd"
        target.write_text(
            f'@"{sys.executable}" "{source}" %*' + chr(13) + chr(10),
            encoding="utf-8",
        )
        return target
    target = tmp_path / "ok-core"
    target.write_bytes((FIXTURES / "fake_core_ok.py").read_bytes())
    target.chmod(0o755)
    return target


@pytest.fixture()
def exit_core(tmp_path):
    if os.name != "posix":
        source = FIXTURES / "fake_core_exit.py"
        target = tmp_path / "exit-core.cmd"
        target.write_text(
            f'@"{sys.executable}" "{source}" %*' + chr(13) + chr(10),
            encoding="utf-8",
        )
        return target
    target = tmp_path / "exit-core"
    target.write_bytes((FIXTURES / "fake_core_exit.py").read_bytes())
    target.chmod(0o755)
    return target


@pytest.fixture()
def hang_core(tmp_path):
    if os.name != "posix":
        source = FIXTURES / "fake_core_hang.py"
        target = tmp_path / "hang-core.cmd"
        target.write_text(
            f'@"{sys.executable}" "{source}" %*' + chr(13) + chr(10),
            encoding="utf-8",
        )
        return target
    target = tmp_path / "hang-core"
    target.write_bytes((FIXTURES / "fake_core_hang.py").read_bytes())
    target.chmod(0o755)
    return target


def policy_for(url, **overrides):
    raw = {
        "repetitions": 1,
        "min_success_ratio": 1.0,
        "min_success_count": 1,
        "startup_timeout_seconds": 6.0,
        "http_timeout_seconds": 3.0,
        "targets": [{"url": url, "expect_status": [200], "expect_substring": "hello-from-local-server"}],
    }
    raw.update(overrides)
    return VerificationPolicy.from_mapping(raw)


def test_runtime_success_with_body_validation(local_http_server, ok_core, workdir_root):
    runner = CoreRuntimeRunner(ok_core, policy=policy_for(local_http_server), workdir_root=workdir_root)
    result = runner.probe_node(make_config())
    assert result.core_started is True
    assert result.passed is True
    assert result.success_count == 1
    assert result.success_ratio == 1.0
    assert result.probes[0].body_validated is True
    assert result.proxy_latency_ms is not None


def test_quorum_is_actually_enforced(local_http_server, ok_core, workdir_root):
    missing = local_http_server.replace("/ok", "/missing")
    policy = VerificationPolicy.from_mapping({
        "repetitions": 2,
        "min_success_ratio": 0.75,
        "min_success_count": 3,
        "startup_timeout_seconds": 6.0,
        "targets": [
            {"url": local_http_server, "expect_status": [200]},
            {"url": missing, "expect_status": [200]},
        ],
    })
    runner = CoreRuntimeRunner(ok_core, policy=policy, workdir_root=workdir_root)
    result = runner.probe_node(make_config())
    # 2/4 succeed. Old code would call this LIVE because at least one passed.
    assert result.success_count == 2
    assert result.success_ratio == 0.5
    assert result.passed is False
    assert result.failure_reason.startswith("runtime_quorum_failed")


def test_optional_probe_failure_does_not_count_against_required_quorum(local_http_server, ok_core, workdir_root):
    missing = local_http_server.replace("/ok", "/missing")
    policy = VerificationPolicy.from_mapping({
        "repetitions": 1,
        "min_success_ratio": 1.0,
        "min_success_count": 1,
        "startup_timeout_seconds": 6.0,
        "targets": [
            {"url": local_http_server, "expect_status": [200], "required": True},
            {"url": missing, "expect_status": [200], "required": False, "kind": "doh"},
        ],
    })
    result = CoreRuntimeRunner(ok_core, policy=policy, workdir_root=workdir_root).probe_node(make_config())
    assert result.passed is True
    assert len(result.probes) == 2
    assert result.probes[1].ok is False
    assert result.probes[1].required is False


def test_domain_config_runtime_does_not_use_preflight_resolved_ip(local_http_server, ok_core, workdir_root, monkeypatch):
    seen = []
    builder, writer, argv_builder, port_getter = client_adapters.BUILDERS["singbox"]

    def capture(config, *, listen_port, resolved_ip=None):
        seen.append(resolved_ip)
        return builder(config, listen_port=listen_port, resolved_ip=resolved_ip)

    monkeypatch.setitem(client_adapters.BUILDERS, "singbox", (capture, writer, argv_builder, port_getter))
    runner = CoreRuntimeRunner(ok_core, policy=policy_for(local_http_server), workdir_root=workdir_root)
    result = runner.probe_node(make_config(host="domain.example"), mode="native")
    assert result.passed is True
    assert seen == [None]


def test_direct_ip_variant_uses_its_ip_natively(local_http_server, ok_core, workdir_root, monkeypatch):
    seen_servers = []
    builder, writer, argv_builder, port_getter = client_adapters.BUILDERS["singbox"]

    def capture(config, *, listen_port, resolved_ip=None):
        built = builder(config, listen_port=listen_port, resolved_ip=resolved_ip)
        seen_servers.append(built["outbounds"][0]["server"])
        return built

    monkeypatch.setitem(client_adapters.BUILDERS, "singbox", (capture, writer, argv_builder, port_getter))
    result = CoreRuntimeRunner(ok_core, policy=policy_for(local_http_server), workdir_root=workdir_root).probe_node(
        make_config(host="8.8.8.8"), mode="native"
    )
    assert result.passed is True
    assert seen_servers == ["8.8.8.8"]


def test_core_startup_failure_is_redacted(exit_core, workdir_root, caplog):
    import logging
    policy = VerificationPolicy.from_mapping({
        "repetitions": 1, "min_success_count": 1,
        "targets": [{"url": "http://127.0.0.1:1/"}],
    })
    runner = CoreRuntimeRunner(exit_core, policy=policy, workdir_root=workdir_root)
    with caplog.at_level(logging.DEBUG):
        result = runner.probe_node(make_config())
    assert result.passed is False
    assert result.failure_reason == "core_startup_failed"
    assert "super-secret-value-123456" not in caplog.text


def test_credentials_never_appear_in_process_argv(local_http_server, ok_core, workdir_root, tmp_path, monkeypatch):
    argv_dump = tmp_path / "argv.txt"
    env = dict(os.environ)
    env["ASE_ARGV_FILE"] = str(argv_dump)
    original_popen = subprocess.Popen
    popen_kwargs = {}

    def popen_with_env(argv, **kwargs):
        # Record only the core launch itself; cleanup helpers spawned
        # later (e.g. taskkill during teardown) use their own flags.
        if "ok-core" in str(argv[0]):
            popen_kwargs.update(kwargs)
        kwargs.setdefault("env", env)
        return original_popen(argv, **kwargs)

    monkeypatch.setattr(client_runtime_module.subprocess, "Popen", popen_with_env)
    runner = CoreRuntimeRunner(ok_core, policy=policy_for(local_http_server), workdir_root=workdir_root)
    assert runner.probe_node(make_config()).passed is True
    argv_text = argv_dump.read_text(encoding="utf-8")
    assert SECRET_IDENTITY not in argv_text
    assert "super-secret-password-42" not in argv_text
    assert "-c" in argv_text
    assert popen_kwargs.get("start_new_session") is (os.name == "posix") or (
        os.name != "posix"
        and popen_kwargs.get("creationflags", 0) & 0x00000200  # CREATE_NEW_PROCESS_GROUP
    )


def test_deadline_excludes_unstarted_candidates(local_http_server, ok_core, workdir_root):
    runner = CoreRuntimeRunner(ok_core, policy=policy_for(local_http_server), workdir_root=workdir_root)
    items = [
        EndpointPreflightResult(config=make_config(suffix=str(i)), preflight_success=True)
        for i in range(3)
    ]
    results, not_tested = run_runtime_stage(items, runner, concurrency=2, soft_deadline_seconds=0.0)
    assert results == []
    assert not_tested == 3


def test_invalid_test_url_is_classified():
    target = VerificationTarget("ftp://invalid/")
    probe = fetch_through_proxy("127.0.0.1", 1, target, timeout=0.1)
    assert probe.ok is False
    assert probe.failure_reason == "invalid_test_url"


def test_hanging_proxy_times_out(local_http_server, hang_core, workdir_root):
    policy = policy_for(local_http_server, http_timeout_seconds=0.5)
    result = CoreRuntimeRunner(hang_core, policy=policy, workdir_root=workdir_root).probe_node(make_config())
    assert result.core_started is True
    assert result.passed is False
    assert result.probes[0].failure_reason == "http_timeout"


def test_each_verification_round_must_meet_round_quorum(ok_core, workdir_root, monkeypatch):
    from auto_subscription_engine.core.verification.models import ApplicationProbeResult

    policy = VerificationPolicy.from_mapping({
        "repetitions": 2,
        "min_success_ratio": 0.75,
        "min_success_count": 3,
        "min_round_success_ratio": 0.75,
        "startup_timeout_seconds": 6.0,
        "targets": [
            {"url": "http://127.0.0.1:1/a", "expect_status": [200]},
            {"url": "http://127.0.0.1:1/b", "expect_status": [200]},
        ],
    })

    def fake_probe(host, port, target, *, timeout, round_index, max_body_bytes):
        # Round 0: 2/2. Round 1: 1/2. Total is 3/4 (75%) but round 1 is flaky.
        ok = round_index == 0 or target.url.endswith("/a")
        return ApplicationProbeResult(
            url=target.url,
            required=True,
            round_index=round_index,
            ok=ok,
            status=200 if ok else 500,
            latency_ms=10.0 if ok else None,
            failure_reason=None if ok else "unexpected_status",
        )

    monkeypatch.setattr(runtime_module, "fetch_through_proxy", fake_probe)
    result = CoreRuntimeRunner(ok_core, policy=policy, workdir_root=workdir_root).probe_node(make_config())
    assert result.success_count == 3
    assert result.success_ratio == 0.75
    assert result.round_success_ratios == [1.0, 0.5]
    assert result.passed is False
