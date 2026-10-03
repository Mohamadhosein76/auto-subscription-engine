from auto_subscription_engine.core.models import OriginFormat, legacy_to_canonical, canonical_to_legacy
from auto_subscription_engine.core.protocols import parse_uri

UUID="11111111-2222-3333-4444-555555555555"

def test_vless_roundtrip_preserves_connection_semantics():
    legacy=parse_uri(f"vless://{UUID}@EXAMPLE.com:443?security=reality&type=ws&path=%2Fws&host=cdn.example&sni=sni.example&pbk=PUB&sid=AB#N")
    c=legacy_to_canonical(legacy)
    assert c.host=="example.com"
    assert c.auth.get("uuid")==UUID
    assert c.transport.kind=="ws"
    assert c.transport.path=="/ws"
    assert c.tls.mode=="reality"
    assert c.tls.server_name=="sni.example"
    assert c.tls.reality_public_key=="PUB"
    back=canonical_to_legacy(c)
    assert back.protocol==legacy.protocol
    assert back.host==legacy.host
    assert back.identity==legacy.identity
    assert back.params["pbk"]=="PUB"


def test_origin_format_is_explicit_metadata():
    c=legacy_to_canonical(parse_uri(f"vless://{UUID}@example.com:443"),origin_format=OriginFormat.URI_LIST)
    assert c.origin_format is OriginFormat.URI_LIST


def test_fingerprint_is_container_independent():
    from auto_subscription_engine.core.ingestion import ingest_content
    from auto_subscription_engine.core.models.fingerprint import compute_canonical_fingerprint
    uri=f"vless://{UUID}@edge.example.com:443?security=tls&type=ws&path=%2Fws&sni=s.example.com#URI"
    a=ingest_content(uri).proxies[0]
    y=f'''proxies:\n- name: YAML\n  type: vless\n  server: edge.example.com\n  port: 443\n  uuid: {UUID}\n  network: ws\n  tls: true\n  sni: s.example.com\n  ws-opts:\n    path: /ws\n'''
    b=ingest_content(y).proxies[0]
    assert compute_canonical_fingerprint(a)==compute_canonical_fingerprint(b)


def test_ingestion_populates_canonical_fingerprint():
    from auto_subscription_engine.core.ingestion import ingest_content
    result=ingest_content(f"vless://{UUID}@edge.example.com:443")
    assert len(result.proxies[0].fingerprint)==64
    int(result.proxies[0].fingerprint,16)
