import base64
from auto_subscription_engine.core.ingestion import ingest_content
from auto_subscription_engine.core.models import OriginFormat


def test_plain_uri_list_and_nested_source_are_separated():
    raw="vless://u@example.com:443\nhttps://example.org/sub\ntrojan://pw@t.example.com:443\n"
    r=ingest_content(raw,source="unit")
    assert [p.protocol for p in r.proxies]==["vless","trojan"]
    assert r.nested_sources==["https://example.org/sub"]
    assert r.detected_format is OriginFormat.URI_LIST
    assert all(p.source=="unit" for p in r.proxies)


def test_base64_subscription_detected():
    raw="vless://u@example.com:443\nhy2://pw@h.example.com:443\n"
    enc=base64.b64encode(raw.encode()).decode()
    r=ingest_content(enc)
    assert [p.protocol for p in r.proxies]==["vless","hysteria2"]
    assert r.detected_format is OriginFormat.BASE64_SUBSCRIPTION


def test_base64_wrapped_clash_yaml_is_detected_as_structured():
    yaml_text='''proxies:\n- name: V\n  type: vless\n  server: v.example.com\n  port: 443\n  uuid: 11111111-2222-3333-4444-555555555555\n'''
    enc=base64.b64encode(yaml_text.encode()).decode()
    r=ingest_content(enc)
    assert r.detected_format is OriginFormat.CLASH_YAML
    assert len(r.proxies)==1 and r.proxies[0].protocol=="vless"
