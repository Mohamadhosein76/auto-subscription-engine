"""Shared feed-stage fixture for platform contract tests.

Builds a minimal, valid post-compat output directory (2 fresh nodes with
qualifying client evidence) so contract tests exercise the real
``run_feed_stage`` platform gate.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

VLESS_A = "vless://11111111-2222-3333-4444-555555555555@93.184.216.10:443?security=tls&sni=a.example&type=tcp#one"
VLESS_B = "vless://11111111-2222-3333-4444-555555555556@host.example:443?security=tls&sni=host.example&type=ws&host=host.example&path=%2Fws#two"
STALE_VLESS = "vless://11111111-2222-3333-4444-555555555557@stale.example:443?security=tls&sni=stale.example&type=tcp#stale"


def _dim(score, **extra):
    return {"score": score, "confidence": 90, **extra}


def _node_row(uri: str, *, compat_verified_at: str | None, client_score: int = 90) -> dict:
    from auto_subscription_engine.core.models.fingerprint import normalize_config
    from auto_subscription_engine.core.protocols import parse_uri
    from auto_subscription_engine.core.utils.identity import config_safe_id

    cfg = normalize_config(parse_uri(uri))
    row = {
        "safe_id": config_safe_id(cfg),
        "protocol": cfg.protocol,
        "status": "live",
        "country_code": "US",
        "asn": 64510,
        "source": "source-a",
        "proxy_latency_ms": 100,
        "security_status": "allow",
        "universal_compatible": True,
        "xray_compatible": "pass",
        "hiddify_compatible": "pass",
        "singbox_compatible": "pass",
        "mihomo_compatible": "pass",
        "network_profile": {
            "direct_ip": True, "ipv4": True, "ipv6": False,
            "tcp": True, "udp": False, "port_443": True,
            "udp_dependency": False,
        },
        "scores": {
            "global": _dim(80),
            "security": _dim(90),
            "operators": {},
            "clients": {
                "v2rayng": _dim(client_score),
                "hiddify": _dim(client_score),
                "nekobox": _dim(client_score),
                "singbox": _dim(client_score),
                "mihomo": _dim(client_score),
            },
        },
    }
    if compat_verified_at is not None:
        row["compat_verified_at"] = compat_verified_at
    return row


def build_feed_output(tmp_path: Path) -> Path:
    """Two fresh qualifying nodes + one stale-evidence node."""
    out = tmp_path / "output"
    out.mkdir()
    now = datetime.now(timezone.utc)
    fresh = (now - timedelta(minutes=5)).isoformat(timespec="seconds")
    stale = (now - timedelta(hours=72)).isoformat(timespec="seconds")

    uris = [VLESS_A, VLESS_B, STALE_VLESS]
    rows = [
        _node_row(VLESS_A, compat_verified_at=fresh),
        _node_row(VLESS_B, compat_verified_at=fresh),
        # stale evidence: gate must exclude it from platform feeds
        _node_row(STALE_VLESS, compat_verified_at=stale, client_score=95),
    ]
    (out / "live_subscription.txt").write_text("\n".join(uris) + "\n", encoding="utf-8", newline="\n")
    (out / "live_subscription_base64.txt").write_text(
        base64.b64encode(("\n".join(uris) + "\n").encode()).decode() + "\n",
        encoding="ascii", newline="\n",
    )
    (out / "live_nodes.json").write_text(json.dumps(rows, indent=2), encoding="utf-8", newline="\n")
    (out / "live_stats.json").write_text(json.dumps({
        "live_total": len(rows), "live_selected": len(rows),
        "compatibility": {"cores_available": {"singbox": True, "xray": True, "hiddify": True, "mihomo": True}},
    }), encoding="utf-8", newline="\n")
    (out / "best.txt").write_text("\n".join(uris[:2]) + "\n", encoding="utf-8", newline="\n")
    return out
