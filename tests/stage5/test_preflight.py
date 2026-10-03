from __future__ import annotations

import socket
import threading

import pytest

from auto_subscription_engine.core.models import ParsedConfig
from auto_subscription_engine.core.verification import (
    FAILURE_DNS,
    FAILURE_NETWORK,
    check_endpoint,
    endpoint_transport,
    run_preflight_stage,
)
import auto_subscription_engine.core.verification.preflight as preflight_module


def cfg(protocol="vless", host="127.0.0.1", port=443, suffix="1"):
    item = ParsedConfig(protocol=protocol, host=host, port=port, identity="id")
    item.fingerprint = f"fp-{suffix}"
    return item


@pytest.fixture()
def listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    stop = False

    def accept_loop():
        while not stop:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            conn.close()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    yield server.getsockname()[1]
    stop = True
    server.close()


def test_tcp_preflight_success(listener):
    result = check_endpoint(cfg(port=listener), timeout=1.0)
    assert result.preflight_success is True
    assert result.tcp_success is True
    assert result.selected_ip == "127.0.0.1"
    assert result.ipv4_success is True
    assert result.tcp_latency_ms is not None


def test_dns_failure_is_explicit(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(socket.gaierror()))
    result = check_endpoint(cfg(host="missing.example"), timeout=0.1)
    assert result.preflight_success is False
    assert result.failure_reason == FAILURE_DNS


def test_udp_native_protocol_skips_meaningless_tcp_gate(monkeypatch):
    def fake_resolve(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, ("203.0.113.7", port))], 1.0

    monkeypatch.setattr(preflight_module, "_resolve", fake_resolve)

    class ForbiddenSocket:
        def __init__(self, *a, **k):
            raise AssertionError("UDP-native preflight must not create a TCP socket")

    monkeypatch.setattr(preflight_module.socket, "socket", ForbiddenSocket)
    result = check_endpoint(cfg(protocol="hysteria2", host="hy.example"), timeout=0.1)
    assert endpoint_transport(result.config) == "udp"
    assert result.preflight_success is True
    assert result.selected_ip == "203.0.113.7"
    assert result.attempts == []
    assert result.tcp_success is False


def test_multiple_addresses_are_observed_and_fastest_success_selected(monkeypatch):
    infos = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, ("203.0.113.10", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, ("2001:db8::10", 443, 0, 0)),
    ]
    monkeypatch.setattr(preflight_module, "_resolve", lambda host, port: (infos, 2.0))

    class FakeSocket:
        calls = 0
        def __init__(self, family, socktype, proto):
            self.family = family
        def settimeout(self, timeout):
            pass
        def connect(self, sockaddr):
            FakeSocket.calls += 1
            if self.family == socket.AF_INET6:
                raise OSError("no ipv6 route")
        def close(self):
            pass

    monkeypatch.setattr(preflight_module.socket, "socket", FakeSocket)
    result = check_endpoint(cfg(host="dual.example"), timeout=0.1)
    assert result.preflight_success is True
    assert result.selected_ip == "203.0.113.10"
    assert len(result.attempts) == 2
    assert result.ipv4_success is True
    assert result.ipv6_success is False


def test_stage_isolates_internal_failures(monkeypatch):
    monkeypatch.setattr(preflight_module, "check_endpoint", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    results = run_preflight_stage([cfg(suffix="a"), cfg(suffix="b")], timeout=0.1, concurrency=2)
    assert len(results) == 2
    assert all(not result.preflight_success for result in results)
    assert all(result.failure_reason == FAILURE_NETWORK for result in results)
