"""Core config builder tests (offline): field fidelity and refusals."""

from __future__ import annotations

import pytest

from auto_subscription_engine.core.clients.compatibility.audit import node_features, unmapped_features
from auto_subscription_engine.core.clients.compatibility.matrix import (
    capabilities_for,
    protocol_common,
    protocol_portability,
    universal_eligible,
)
from auto_subscription_engine.core.clients.builders.mihomo import build_mihomo_config, build_mihomo_proxy
from auto_subscription_engine.core.clients.builders.xray import build_xray_config, build_xray_outbound
from auto_subscription_engine.core.models import ParsedConfig
from auto_subscription_engine.core.models.fingerprint import normalize_config
from auto_subscription_engine.core.protocols import parse_uri
from auto_subscription_engine.core.clients.builders.singbox import UnsupportedNodeError, build_outbound


def cfg(uri: str) -> ParsedConfig:
    return normalize_config(parse_uri(uri))


VLESS_REALITY = (
    "vless://11111111-2222-3333-4444-555555555555@example.com:443"
    "?security=reality&sni=www.example.org&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"
    "&sid=6ba85179&type=tcp&flow=xtls-rprx-vision#reality-node"
)
VLESS_WS = (
    "vless://11111111-2222-3333-4444-555555555555@example.com:443"
    "?security=tls&sni=tls.example.org&host=ws.example.org&path=%2Fws%2Fpath"
    "&type=ws&alpn=h2%2Chttp%2F1.1#ws-node"
)
VLESS_GRPC = (
    "vless://11111111-2222-3333-4444-555555555555@example.com:443"
    "?security=tls&sni=grpc.example.org&serviceName=grpc-svc&type=grpc#grpc-node"
)
VMESS_WS_JSON = {
    "v": "2", "ps": "VMess WS", "add": "vmess.example.com", "port": "443",
    "id": "12345678-1234-1234-1234-123456789abc", "aid": "0", "scy": "auto",
    "net": "ws", "host": "vmess.host.org", "path": "/vmess",
    "tls": "tls", "sni": "vmess.sni.org",
}


def vmess_ws_uri() -> str:
    import base64
    import json

    return "vmess://" + base64.b64encode(
        json.dumps(VMESS_WS_JSON).encode("utf-8")
    ).decode("ascii")


TROJAN_WS = (
    "trojan://secretpassword@198.51.100.7:443"
    "?security=tls&sni=troj.example.com&host=wsfast.example.net&type=ws"
    "&path=%2Ftws&alpn=http%2F1.1&fp=chrome#trojan-ws"
)
SS_SIP002 = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM=@192.0.2.10:8388#ss-node"
HY2 = "hysteria2://hypass@203.0.113.5:443/?sni=hy2.example.com&insecure=1#hy2-node"


# ---------------------------------------------------------------------------
# Xray builder
# ---------------------------------------------------------------------------


def test_xray_vless_reality_fields_preserved():
    outbound = build_xray_outbound(cfg(VLESS_REALITY))
    assert outbound["protocol"] == "vless"
    user = outbound["settings"]["vnext"][0]["users"][0]
    assert user["id"] == "11111111-2222-3333-4444-555555555555"
    assert user["flow"] == "xtls-rprx-vision"
    stream = outbound["streamSettings"]
    assert stream["security"] == "reality"
    reality = stream["realitySettings"]
    assert (
        reality["publicKey"]
        == "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"
    )
    assert reality["shortId"] == "6ba85179"
    assert reality["serverName"] == "www.example.org"
    assert reality["fingerprint"] == "chrome"


def test_xray_vless_ws_host_path_alpn():
    outbound = build_xray_outbound(cfg(VLESS_WS))
    stream = outbound["streamSettings"]
    assert stream["network"] == "ws"
    assert stream["wsSettings"]["path"] == "/ws/path"
    assert stream["wsSettings"]["headers"]["Host"] == "ws.example.org"
    tls = stream["tlsSettings"]
    assert tls["serverName"] == "tls.example.org"
    assert tls["alpn"] == ["h2", "http/1.1"]
    assert tls["allowInsecure"] is False


def test_xray_grpc_service_name():
    outbound = build_xray_outbound(cfg(VLESS_GRPC))
    assert outbound["streamSettings"]["grpcSettings"]["serviceName"] == "grpc-svc"


def test_xray_vmess_ws():
    outbound = build_xray_outbound(cfg(vmess_ws_uri()))
    assert outbound["protocol"] == "vmess"
    user = outbound["settings"]["vnext"][0]["users"][0]
    assert user["security"] == "auto"
    assert outbound["streamSettings"]["wsSettings"]["path"] == "/vmess"


def test_xray_trojan_ws_full_mapping():
    outbound = build_xray_outbound(cfg(TROJAN_WS))
    assert outbound["protocol"] == "trojan"
    stream = outbound["streamSettings"]
    assert stream["network"] == "ws"
    assert stream["wsSettings"]["path"] == "/tws"
    assert stream["wsSettings"]["headers"]["Host"] == "wsfast.example.net"
    assert stream["tlsSettings"]["serverName"] == "troj.example.com"
    assert stream["tlsSettings"]["alpn"] == ["http/1.1"]


def test_xray_ss_sip002():
    outbound = build_xray_outbound(cfg(SS_SIP002))
    server = outbound["settings"]["servers"][0]
    assert server["method"] == "aes-256-gcm"
    assert server["password"] == "password123"


def test_xray_refuses_hysteria2():
    with pytest.raises(UnsupportedNodeError) as excinfo:
        build_xray_outbound(cfg(HY2))
    assert "unsupported_protocol" in excinfo.value.reason


def test_xray_refuses_ss_plugin():
    uri = SS_SIP002.replace("#ss-node", "?plugin=obfs-local%3Bobfs%3Dhttp")
    with pytest.raises(UnsupportedNodeError) as excinfo:
        build_xray_outbound(cfg(uri))
    assert "ss_plugin" in excinfo.value.reason


def test_xray_refuses_unknown_flow():
    uri = VLESS_REALITY.replace("flow=xtls-rprx-vision", "flow=xtls-rprx-direct")
    with pytest.raises(UnsupportedNodeError) as excinfo:
        build_xray_outbound(cfg(uri))
    assert "unsupported_option:flow" in excinfo.value.reason


def test_xray_config_shape():
    config = build_xray_config(cfg(VLESS_WS), listen_port=18777)
    inbound = config["inbounds"][0]
    assert inbound["port"] == 18777
    assert inbound["listen"] == "127.0.0.1"
    assert inbound["protocol"] == "http"


def test_xray_allow_insecure_copied_verbatim():
    uri = VLESS_WS.replace("&type=ws", "&type=ws&allowInsecure=1")
    tls = build_xray_outbound(cfg(uri))["streamSettings"]["tlsSettings"]
    assert tls["allowInsecure"] is True


# ---------------------------------------------------------------------------
# Hiddify builder (sing-box schema)
# ---------------------------------------------------------------------------


def test_hiddify_uses_singbox_schema_and_supports_hy2():
    config = cfg(HY2)
    outbound = build_outbound(config)
    assert outbound["type"] == "hysteria2"
    assert outbound["password"] == "hypass"
    assert outbound["tls"]["insecure"] is True


def test_hiddify_vless_reality():
    outbound = build_outbound(cfg(VLESS_REALITY))
    assert outbound["type"] == "vless"
    assert outbound["tls"]["reality"]["short_id"] == "6ba85179"


# ---------------------------------------------------------------------------
# Mihomo builder
# ---------------------------------------------------------------------------


def test_mihomo_vless_reality():
    proxy = build_mihomo_proxy(cfg(VLESS_REALITY))
    assert proxy["type"] == "vless"
    assert proxy["reality-opts"]["public-key"].startswith("SbVK")
    assert proxy["reality-opts"]["short-id"] == "6ba85179"
    assert proxy["client-fingerprint"] == "chrome"
    assert proxy["servername"] == "www.example.org"


def test_mihomo_trojan_uses_sni_field_not_servername():
    """Mihomo's trojan client verifies against ``sni`` (real-tunnel proven)."""
    proxy = build_mihomo_proxy(cfg(TROJAN_WS))
    assert proxy["sni"] == "troj.example.com"
    assert "servername" not in proxy
    assert proxy["network"] == "ws"
    assert proxy["ws-opts"]["headers"]["Host"] == "wsfast.example.net"


def test_mihomo_vmess_ws():
    proxy = build_mihomo_proxy(cfg(vmess_ws_uri()))
    assert proxy["type"] == "vmess"
    assert proxy["cipher"] == "auto"
    assert proxy["ws-opts"]["path"] == "/vmess"
    assert proxy["servername"] == "vmess.sni.org"


def test_mihomo_hysteria2():
    proxy = build_mihomo_proxy(cfg(HY2))
    assert proxy["type"] == "hysteria2"
    assert proxy["skip-cert-verify"] is True
    assert proxy["sni"] == "hy2.example.com"


def test_mihomo_refuses_unsupported_ss_plugin():
    uri = SS_SIP002.replace("#ss-node", "?plugin=shadow-tls%3Bv%3D1")
    with pytest.raises(UnsupportedNodeError):
        build_mihomo_proxy(cfg(uri))


def test_mihomo_config_shape():
    config = build_mihomo_config(cfg(SS_SIP002), listen_port=18666)
    assert config["mixed-port"] == 18666
    assert config["mode"] == "rule"
    assert config["rules"] == ["MATCH,proxy"]
    assert len(config["proxies"]) == 1


# ---------------------------------------------------------------------------
# Capability matrix + parser fidelity audit
# ---------------------------------------------------------------------------


def test_matrix_hysteria2_unsupported_by_xray_only():
    features = node_features(cfg(HY2))
    caps = capabilities_for(features)
    assert caps["xray"].supported is False
    assert "unsupported_protocol" in caps["xray"].detail
    assert caps["singbox"].supported and caps["hiddify"].supported
    assert caps["mihomo"].supported
    assert universal_eligible(features) is False


def test_matrix_vless_reality_common():
    features = node_features(cfg(VLESS_REALITY))
    assert universal_eligible(features) is True
    assert protocol_common("vless") is True


def test_protocol_portability_values():
    assert protocol_portability("vless") == 1.0
    assert protocol_portability("hysteria2") == 0.75


def test_audit_flags_ss_plugin_and_xhttp():
    uri = SS_SIP002.replace("#ss-node", "?plugin=obfs-local%3Bobfs%3Dhttp")
    flags = unmapped_features(cfg(uri))
    assert any(flag.startswith("ss_plugin:") for flag in flags)
    uri2 = VLESS_WS.replace("type=ws", "type=xhttp")
    xhttp = cfg(uri2)
    assert not unmapped_features(xhttp)
    caps = capabilities_for(node_features(xhttp))
    assert caps["xray"].supported is True
    assert caps["mihomo"].supported is True
    assert caps["singbox"].supported is False
    assert caps["hiddify"].supported is False


def test_audit_flags_unknown_vmess_json_fields():
    import base64
    import json as jsonlib

    obj = dict(VMESS_WS_JSON)
    obj["verify"] = "cert"
    uri = "vmess://" + base64.b64encode(jsonlib.dumps(obj).encode()).decode()
    flags = unmapped_features(cfg(uri))
    assert "vmess_verify_json" in flags


def test_audit_ipv6_uri_parse():
    uri = (
        "vless://11111111-2222-3333-4444-555555555555@[2001:db8::1]:443"
        "?security=tls&sni=v6.example.com&type=tcp#v6"
    )
    config = cfg(uri)
    assert config.host == "2001:db8::1"
    assert config.port == 443
    outbound = build_xray_outbound(config)
    assert outbound["settings"]["vnext"][0]["address"] == "2001:db8::1"
    proxy = build_mihomo_proxy(config)
    assert proxy["server"] == "2001:db8::1"
