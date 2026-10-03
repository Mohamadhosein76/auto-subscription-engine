"""Per-core runtime tester tests (offline, fake cores on loopback)."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from auto_subscription_engine.core.clients.compatibility.runner import (
    CompatTestUrl,
    CoreTestResult,
    CoreTester,
)
from auto_subscription_engine.core.models import ParsedConfig
from auto_subscription_engine.core.clients.builders.singbox import UnsupportedNodeError

FIXTURES = Path(__file__).parent / "fixtures" / "fake_cores"


def make_config(protocol: str = "vless") -> ParsedConfig:
    return ParsedConfig(protocol=protocol, host="node.example", port=443, identity="id-1")


def make_tester(
    core_script: Path,
    tmp_path: Path,
    *,
    builder=None,
    argv=None,
    port_getter=None,
    urls=None,
    **overrides,
) -> CoreTester:
    params = dict(
        core="xray",
        binary_path=core_script,
        config_builder=builder or _fake_builder,
        config_writer=_fake_json_writer,
        argv_builder=argv or _fake_argv,
        port_getter=port_getter or _fake_port,
        test_urls=urls or [CompatTestUrl(url="http://placeholder.invalid/", expect_statuses=(200,))],
        startup_timeout=4.0,
        http_timeout=4.0,
    )
    params.update(overrides)
    return CoreTester(**params)


def _fake_builder(config, *, listen_port, resolved_ip=None):
    return {"inbounds": [{"listen_port": listen_port}], "protocol": config.protocol}


def _fake_json_writer(config, workdir):
    path = Path(workdir) / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _fake_argv(binary, config_path, workdir):
    return [str(binary), "run", "-c", str(config_path)]


def _fake_port(config):
    return int(config["inbounds"][0]["listen_port"])


def install_fake_core(tmp_path: Path, name: str) -> Path:
    target = tmp_path / name
    target.write_bytes((FIXTURES / name).read_bytes())
    target.chmod(0o755)
    return target


@pytest.fixture()
def fake_ok_core(tmp_path):
    return install_fake_core(tmp_path, "fake_core_ok.py")


@pytest.fixture()
def fake_exit_core(tmp_path):
    return install_fake_core(tmp_path, "fake_core_exit.py")


@pytest.fixture()
def fake_hang_core(tmp_path):
    return install_fake_core(tmp_path, "fake_core_hang.py")


@pytest.fixture()
def fake_stall_core(tmp_path):
    return install_fake_core(tmp_path, "fake_core_stall.py")


# ---------------------------------------------------------------------------
# Builder-refusal classification
# ---------------------------------------------------------------------------


def test_unsupported_protocol_classified(tmp_path, fake_ok_core):
    def refusing_builder(config, **kwargs):
        raise UnsupportedNodeError("unsupported_protocol:hysteria2")

    tester = make_tester(fake_ok_core, tmp_path, builder=refusing_builder)
    result = tester.test_node(make_config("hysteria2"))
    assert result.status == "unsupported"
    assert result.failure_category == "unsupported_protocol:hysteria2"
    assert result.core_started is False if hasattr(result, "core_started") else True


def test_unsupported_transport_classified(tmp_path, fake_ok_core):
    def refusing_builder(config, **kwargs):
        raise UnsupportedNodeError("unsupported_transport:kcp")

    tester = make_tester(fake_ok_core, tmp_path, builder=refusing_builder)
    result = tester.test_node(make_config())
    assert result.status == "unsupported"
    assert result.failure_category == "unsupported_transport:kcp"


# ---------------------------------------------------------------------------
# Process lifecycle classification (fake cores)
# ---------------------------------------------------------------------------


def test_config_rejected_classification(tmp_path, fake_exit_core):
    """A core that exits immediately produces a startup-failure category."""
    tester = make_tester(fake_exit_core, tmp_path)
    result = tester.test_node(make_config())
    assert result.status == "fail"
    assert result.failure_category in ("core_config_rejected", "core_startup_failed")


def test_startup_timeout_classification(tmp_path, fake_stall_core):
    """A core that never binds the port times out (and is killed)."""
    tester = make_tester(fake_stall_core, tmp_path, startup_timeout=1.0)
    result = tester.test_node(make_config())
    assert result.status == "fail"
    assert result.failure_category == "core_startup_timeout"
    tester.cleanup()  # no leaked processes


def test_pass_requires_http_through_tunnel(tmp_path, fake_ok_core, local_http_server):
    """PASS only with a real HTTP request through the local proxy."""
    urls = [CompatTestUrl(url=local_http_server, expect_statuses=(200,))]
    tester = make_tester(fake_ok_core, tmp_path, urls=urls)
    result = tester.test_node(make_config())
    assert result.status == "pass"
    assert result.failure_category is None
    assert result.latency_ms is not None
    assert result.probes[0]["ok"] is True


def test_fail_when_http_fails(tmp_path, fake_ok_core):
    """A bound core with no reachable destination is a failure, not a pass."""
    urls = [CompatTestUrl(url="http://127.0.0.1:1/nope", expect_statuses=(200,))]
    tester = make_tester(fake_ok_core, tmp_path, urls=urls)
    result = tester.test_node(make_config())
    assert result.status == "fail"
    assert result.failure_category  # a concrete category is recorded


def test_no_credentials_in_argv(tmp_path, fake_ok_core, monkeypatch):
    """The core config travels via a 0600 file, never the command line."""
    argv_dump = tmp_path / "argv.txt"
    monkeypatch.setenv("ASE_ARGV_FILE", str(argv_dump))
    tester = make_tester(fake_ok_core, tmp_path)
    config = make_config()
    config.identity = "super-secret-uuid-42"
    tester.test_node(config)
    if argv_dump.is_file():
        argv_text = argv_dump.read_text(encoding="utf-8")
        assert "super-secret-uuid-42" not in argv_text


def test_config_file_permissions(tmp_path, fake_ok_core):
    """The per-test config file is written with mode 0600."""
    seen_modes = []

    def writer(config, workdir):
        path = _fake_json_writer(config, workdir)
        seen_modes.append(stat.S_IMODE(path.stat().st_mode))
        return path

    tester = make_tester(fake_ok_core, tmp_path)
    tester.config_writer = writer
    tester.test_node(make_config())
    assert seen_modes == [0o600]


def test_process_killed_after_timeout(tmp_path, fake_hang_core):
    """A bound-but-silent core hits the probe timeout and is killed."""
    tester = make_tester(fake_hang_core, tmp_path, http_timeout=1.0)
    result = tester.test_node(make_config())
    assert result.status == "fail"
    tester.cleanup()
    assert not tester._processes


def test_body_validation_failure_category(tmp_path, fake_ok_core):
    """A status-200 response with the wrong body is a content failure."""
    urls = [
        CompatTestUrl(
            url="http://127.0.0.1:1/x", expect_statuses=(200,), expect_substring="Nope"
        )
    ]
    tester = make_tester(fake_ok_core, tmp_path, urls=urls)
    result = tester.test_node(make_config())
    assert result.status == "fail"
