"""Temp path and port allocation contract tests (run on the real platform)."""

from __future__ import annotations

import socket
from pathlib import Path

from auto_subscription_engine.core.platform import temp_root
from auto_subscription_engine.core.platform.paths import runtime_dir


def test_temp_root_exists_and_is_absolute():
    root = temp_root()
    assert root.is_absolute() or root.resolve().is_absolute()
    assert Path(root).exists()


def test_runtime_dir_resolves_relative():
    resolved = runtime_dir("some-core-bin")
    assert resolved.is_absolute()
    assert resolved.name == "some-core-bin"


def test_core_workdirs_live_in_temp_root(tmp_path):
    """CoreRuntimeManager creates workdirs under the given root (no /tmp)."""
    from auto_subscription_engine.core.clients.runtime import CoreRuntimeManager
    from auto_subscription_engine.core.models import ParsedConfig

    from helpers_platform import (
        _fake_argv,
        _fake_builder,
        _fake_json_writer,
        _fake_port,
        install_fake_core,
    )

    binary = install_fake_core(tmp_path, "fake_core_ok.py")
    workdir_root = tmp_path / "workdirs"
    manager = CoreRuntimeManager(
        {"xray": binary}, startup_timeout=8.0, workdir_root=workdir_root
    )
    config = ParsedConfig(protocol="vless", host="node.example", port=443, identity="id-1")
    session = manager.open_with_adapter(
        "xray",
        binary,
        config,
        builder=_fake_builder,
        writer=_fake_json_writer,
        argv_builder=_fake_argv,
        port_getter=_fake_port,
    )
    try:
        assert str(workdir_root) in str(session.workdir)
        # No POSIX temp path may leak onto Windows.
        assert "C:\\tmp" not in str(session.workdir)
    finally:
        session.close()


def test_port_allocation_is_unique_under_concurrency():
    """Stage-12 race fix: parallel allocations never return the same port."""
    from concurrent.futures import ThreadPoolExecutor

    from auto_subscription_engine.core.clients.builders.singbox import allocate_port

    with ThreadPoolExecutor(16) as pool:
        ports = list(pool.map(lambda _: allocate_port(), range(200)))
    assert len(ports) == len(set(ports)), "duplicate ports allocated"


def test_allocate_port_binds_successfully():
    port = None
    from auto_subscription_engine.core.clients.builders.singbox import allocate_port

    port = allocate_port()
    # The allocator must hand out bindable ports: prove it on one of them.
    sock = socket.socket()
    sock.bind(("127.0.0.1", port if isinstance(port, int) else int(port)))
    sock.close()
