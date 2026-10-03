"""Shared fixtures and helpers for the test suite."""

from __future__ import annotations

import base64
import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    """Read a text fixture file."""
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


def make_vmess_uri(
    obj: dict[str, object],
    *,
    urlsafe: bool = False,
    pad: bool = True,
) -> str:
    """Build a vmess:// URI from a JSON payload (base64-encoded)."""
    raw = json.dumps(obj).encode("utf-8")
    if urlsafe:
        encoded = base64.urlsafe_b64encode(raw).decode("ascii")
    else:
        encoded = base64.b64encode(raw).decode("ascii")
    if not pad:
        encoded = encoded.rstrip("=")
    return "vmess://" + encoded


def default_vmess_obj(**overrides: object) -> dict[str, object]:
    """A standard VMess JSON payload for tests."""
    obj: dict[str, object] = {
        "v": "2",
        "ps": "Test VMess",
        "add": "vmess.example.com",
        "port": "443",
        "id": "12345678-1234-1234-1234-123456789abc",
        "aid": "0",
        "scy": "auto",
        "net": "tcp",
        "type": "none",
        "host": "",
        "path": "",
        "tls": "",
        "sni": "",
    }
    obj.update(overrides)
    return obj


import http.server
import threading


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.startswith("/ok"):
            body = b"hello-from-local-server"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"nope")

    def log_message(self, *args):  # silence
        pass


import pytest


@pytest.fixture()
def local_http_server():
    """Tiny loopback HTTP server: /ok -> 200 with a known body."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/ok"
    server.shutdown()
    server.server_close()
