from __future__ import annotations
import base64
import json
from pathlib import Path
import yaml

from auto_subscription_engine.core.feeds import FeedOptions, run_feed_stage, verify_feed_outputs
from auto_subscription_engine.core.models.fingerprint import normalize_config
from auto_subscription_engine.core.protocols import parse_uri
from auto_subscription_engine.core.utils.identity import config_safe_id

VLESS1 = "vless://11111111-2222-3333-4444-555555555555@93.184.216.10:443?security=tls&sni=a.example&type=tcp#one"
VLESS2 = "vless://11111111-2222-3333-4444-555555555556@host.example:443?security=tls&sni=host.example&type=ws&host=host.example&path=%2Fws#two"
TROJAN = "trojan://password@198.51.100.10:443?security=tls&sni=t.example&type=tcp#three"
SS = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM=@192.0.2.10:443#four"
URIS = [VLESS1, VLESS2, TROJAN, SS]


def _dim(score, confidence=90, **extra):
    return {"score": score, "confidence": confidence, **extra}


def _build_output(tmp_path: Path) -> Path:
    out = tmp_path / "output"
    out.mkdir()
    rows = []
    scores = [92, 75, 58, 45]
    security = [95, 85, 82, 55]
    for i, (uri, global_score, sec) in enumerate(zip(URIS, scores, security)):
        cfg = normalize_config(parse_uri(uri))
        sid = config_safe_id(cfg)
        mci = _dim(90 - i * 5, fresh=True) if i < 2 else _dim(None, confidence=0, fresh=False)
        irancell = _dim(None, confidence=0, fresh=False)
        rows.append({
            "safe_id": sid,
            "protocol": cfg.protocol,
            "status": "live",
            "country_code": "US" if i < 3 else "DE",
            "asn": 64510 + i,
            "prefix": f"198.51.{i}.0/24",
            "source": "source-a" if i < 2 else "source-b",
            "proxy_latency_ms": 100 + i * 50,
            "security_status": "allow",
            "universal_compatible": i != 2,
            "xray_compatible": "pass",
            "hiddify_compatible": "pass",
            "singbox_compatible": "pass",
            "mihomo_compatible": "pass",
            "network_profile": {
                "direct_ip": i != 1,
                "ipv4": True,
                "ipv6": False,
                "tcp": True,
                "udp": False,
                "port_443": True,
                "udp_dependency": False,
            },
            "scores": {
                "global": _dim(global_score),
                "reliability": _dim(90 - i * 10),
                "latency": _dim(95 - i * 10),
                "security": _dim(sec),
                "freshness": _dim(100),
                "connectivity": _dim(100),
                "operators": {"mci": mci, "irancell": irancell, "rightel": _dim(None, 0, fresh=False), "fixed": _dim(None, 0, fresh=False)},
                "clients": {
                    "v2rayng": _dim(90 - i * 5),
                    "hiddify": _dim(88 - i * 5),
                    "nekobox": _dim(86 - i * 5),
                    "singbox": _dim(86 - i * 5),
                    "mihomo": _dim(84 - i * 5),
                },
            },
        })
    (out / "live_subscription.txt").write_text("\n".join(URIS) + "\n", encoding="utf-8")
    (out / "live_subscription_base64.txt").write_text(base64.b64encode(("\n".join(URIS)+"\n").encode()).decode()+"\n")
    (out / "live_nodes.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (out / "live_stats.json").write_text(json.dumps({
        "live_total": len(rows), "live_selected": len(rows),
        "compatibility": {"cores_available": {"singbox": True, "xray": True, "hiddify": True, "mihomo": True}},
    }), encoding="utf-8")
    (out / "best.txt").write_text("\n".join(URIS[:2]) + "\n", encoding="utf-8")
    return out


def test_stage10_builds_score_aware_feeds_and_legacy_main(tmp_path: Path):
    out = _build_output(tmp_path)
    manifest = run_feed_stage(FeedOptions(output_dir=out, config_path=Path("config/feeds.yaml")))
    assert manifest["engine"] == "score-aware-feed-v2"
    universal = (out / "clients/universal.txt").read_text().splitlines()
    assert TROJAN not in universal
    assert (out / "live_subscription.txt").read_text() == (out / "clients/universal.txt").read_text()
    recommended = (out / "profiles/recommended.txt").read_text().splitlines()
    assert VLESS1 in recommended and VLESS2 in recommended
    secure = (out / "profiles/secure.txt").read_text().splitlines()
    assert SS not in secure
    direct_ip = (out / "networks/direct-ip.txt").read_text().splitlines()
    assert VLESS2 not in direct_ip and VLESS1 in direct_ip
    assert verify_feed_outputs(out) == []


def test_operator_feed_requires_fresh_scored_evidence(tmp_path: Path):
    out = _build_output(tmp_path)
    run_feed_stage(FeedOptions(output_dir=out, config_path=Path("config/feeds.yaml")))
    mci = out / "operators/mci/v2rayng.txt"
    assert mci.is_file()
    assert mci.read_text().splitlines() == [VLESS1, VLESS2]
    assert not (out / "operators/irancell/v2rayng.txt").exists()
    ir_manifest = json.loads((out / "operators/irancell/manifest.json").read_text())
    assert ir_manifest["fresh_evidence_nodes"] == 0


def test_client_native_artifacts_are_generated_from_selected_configs(tmp_path: Path):
    out = _build_output(tmp_path)
    run_feed_stage(FeedOptions(output_dir=out, config_path=Path("config/feeds.yaml")))
    singbox = json.loads((out / "clients/singbox.json").read_text())
    mihomo = yaml.safe_load((out / "clients/mihomo.yaml").read_text())
    assert len(singbox["outbounds"]) == 4
    assert len(mihomo["proxies"]) == 4
    assert len({p["name"] for p in mihomo["proxies"]}) == 4


def test_feed_manifest_and_score_metadata_are_credential_free(tmp_path: Path):
    out = _build_output(tmp_path)
    run_feed_stage(FeedOptions(output_dir=out, config_path=Path("config/feeds.yaml")))
    for path in [out / "feed_manifest.json", out / "operators/mci/manifest.json", out / "clients/manifest.json"]:
        text = path.read_text()
        assert "://" not in text
        assert "11111111-2222-3333-4444-555555555555" not in text
        assert '"password"' not in text
