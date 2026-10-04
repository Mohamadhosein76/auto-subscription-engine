"""Cross-platform public contract tests: platform-neutral artifact bytes.

Every text artifact the engine publishes must be byte-identical whether
generated on Linux or Windows: LF endings everywhere, no CRLF drift.
"""

from __future__ import annotations

import base64
import json

from auto_subscription_engine.core.feeds.engine import _write_uri_feed
from auto_subscription_engine.core.platform import is_windows


def test_uri_feed_is_lf_stable(tmp_path):
    class Candidate:
        def __init__(self, uri):
            self.uri = uri

    path = tmp_path / "feed.txt"
    _write_uri_feed(path, [Candidate("vless://a@b:1#x"), Candidate("ss://c@d:2#y")])
    raw = path.read_bytes()
    assert b"\r" not in raw, "feed bytes must never contain CR"
    decoded = base64.b64decode(
        path.with_name("feed_base64.txt").read_text(encoding="ascii").strip()
    )
    assert decoded == raw


def test_json_writes_are_lf_stable(tmp_path):
    payload = {"a": 1, "b": "x"}
    path = tmp_path / "state.json"
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8", newline="\n")
    assert b"\r" not in path.read_bytes()


def test_base64_roundtrip_matches_on_this_platform(tmp_path):
    body = "vless://a@b:1#x\n" + "ss://c@d:2#y\n"
    path = tmp_path / "sub.txt"
    path.write_text(body, encoding="utf-8", newline="\n")
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    b64_path = tmp_path / "sub_base64.txt"
    b64_path.write_text(encoded + "\n", encoding="ascii", newline="\n")
    assert base64.b64decode(b64_path.read_text(encoding="ascii").strip()).decode(
        "utf-8"
    ) == path.read_text(encoding="utf-8")
