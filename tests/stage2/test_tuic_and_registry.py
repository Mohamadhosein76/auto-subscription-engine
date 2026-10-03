from auto_subscription_engine.core.models import CANONICAL_PROTOCOLS
from auto_subscription_engine.core.protocols import available_protocols, parse_uri
from auto_subscription_engine.core.models.validation import validate_config


def test_tuic_uri_parses_and_is_runtime_enabled_once_stage7_adapters_exist():
    uri=("tuic://3618921b-adeb-4bd3-a2a0-f98b72a674b1:secret@8.8.8.8:443"
         "?allow_insecure=1&alpn=h3&congestion_control=bbr&sni=example.com&udp_relay_mode=native#TUIC")
    cfg=parse_uri(uri)
    assert cfg.protocol=="tuic"
    assert cfg.identity=="3618921b-adeb-4bd3-a2a0-f98b72a674b1"
    assert cfg.params["password"]=="secret"
    assert cfg.params["congestion_control"]=="bbr"
    assert cfg.name=="TUIC"
    # Stage 7 boundary: native runtime adapters now exist for compatible cores.
    assert validate_config(cfg).ok


def test_registry_exposes_stage2_protocol_set():
    assert set(available_protocols())==set(CANONICAL_PROTOCOLS)
