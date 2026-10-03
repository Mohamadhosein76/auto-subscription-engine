"""Tests for IP geolocation: cache, batching, rate limit, graceful failure.

The provider endpoint is a local fake HTTP server (no public internet).
"""

from __future__ import annotations

import http.server
import json
import threading

import pytest
import requests

from auto_subscription_engine.core.network.geo import GeoInfo, GeoResolver, GeoSettings


class FakeGeoHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"[]")
        self.server.hit_count += 1
        payload = []
        for ip in body:
            if ip == "198.51.100.66":
                payload.append({"status": "fail", "message": "reserved range", "query": ip})
            else:
                payload.append({
                    "status": "success",
                    "country": "Germany",
                    "countryCode": "DE",
                    "query": ip,
                })
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        self.server.hit_count += 1
        ip = self.path.split("/json/")[1].split("?")[0]
        data = json.dumps({
            "status": "success", "country": "Netherlands",
            "countryCode": "NL", "query": ip,
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # silence
        pass


@pytest.fixture()
def fake_geo_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeGeoHandler)
    server.hit_count = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def make_resolver(server, **overrides):
    settings = GeoSettings(
        batch_url=f"http://127.0.0.1:{server.server_address[1]}/batch?fields=status",
        single_url=f"http://127.0.0.1:{server.server_address[1]}/json/{{ip}}",
        timeout_seconds=3.0,
        batch_size=2,  # force multiple batches in tests
        batch_rate_per_minute=60000,  # effectively no waiting
        max_lookups=100,
    )
    return GeoResolver(settings if not overrides else replace_settings(settings, **overrides))


def replace_settings(settings, **overrides):
    from dataclasses import replace

    return replace(settings, **overrides)


def test_batch_lookup_success_and_mapping(fake_geo_server):
    resolver = make_resolver(fake_geo_server)
    result = resolver.lookup_many(["198.51.100.1", "198.51.100.2"])
    assert result["198.51.100.1"] == GeoInfo("DE", "Germany")
    assert result["198.51.100.2"] == GeoInfo("DE", "Germany")


def test_provider_failure_maps_to_unknown(fake_geo_server):
    resolver = make_resolver(fake_geo_server)
    result = resolver.lookup_many(["198.51.100.66"])
    assert result["198.51.100.66"] == GeoInfo("UNKNOWN", "Unknown")


def test_cache_prevents_repeat_requests(fake_geo_server):
    resolver = make_resolver(fake_geo_server)
    resolver.lookup_many(["198.51.100.1", "198.51.100.2"])
    first_hits = fake_geo_server.hit_count
    # Same IPs again: served entirely from cache.
    resolver.lookup_many(["198.51.100.1", "198.51.100.2"])
    assert fake_geo_server.hit_count == first_hits


def test_lookup_one_fallback(fake_geo_server):
    resolver = make_resolver(fake_geo_server)
    info = resolver.lookup_one("198.51.100.9")
    assert info == GeoInfo("NL", "Netherlands")


def test_rate_limiter_enforces_interval():
    from auto_subscription_engine.core.network.geo import _RateLimiter
    import time

    limiter = _RateLimiter(min_interval_seconds=0.15)
    start = time.monotonic()
    limiter.wait()
    limiter.wait()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.14


def test_max_lookups_budget_returns_unknown_for_rest(fake_geo_server):
    resolver = make_resolver(fake_geo_server, max_lookups=1)
    result = resolver.lookup_many(["198.51.100.1", "198.51.100.3", "198.51.100.4"])
    assert result["198.51.100.1"].known is True
    assert result["198.51.100.3"] == GeoInfo()
    assert result["198.51.100.4"] == GeoInfo()


def test_provider_outage_degrades_to_unknown():
    settings = GeoSettings(
        batch_url="http://127.0.0.1:1/batch",  # nothing listens there
        single_url="http://127.0.0.1:1/json/{ip}",
        timeout_seconds=0.5,
        batch_size=10,
        batch_rate_per_minute=60000,
        max_lookups=10,
    )
    resolver = GeoResolver(settings)
    result = resolver.lookup_many(["198.51.100.1", "198.51.100.2"])
    assert all(info == GeoInfo() for info in result.values())
