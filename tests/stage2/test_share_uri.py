from auto_subscription_engine.core.ingestion import ingest_content
from auto_subscription_engine.core.serialization import to_share_uri
from auto_subscription_engine.core.protocols import parse_uri


def test_tuic_canonical_serializes_to_parseable_share_uri():
    raw='''proxies:\n- name: T\n  type: tuic\n  server: t.example.com\n  port: 443\n  uuid: 22222222-3333-4444-5555-666666666666\n  password: pw\n  sni: s.example.com\n  congestion-controller: bbr\n  udp-relay-mode: native\n'''
    c=ingest_content(raw).proxies[0]
    uri=to_share_uri(c)
    parsed=parse_uri(uri)
    assert parsed.protocol=="tuic"
    assert parsed.identity=="22222222-3333-4444-5555-666666666666"
    assert parsed.params["password"]=="pw"
    assert parsed.params["sni"]=="s.example.com"


def test_clash_vless_serializes_to_share_uri():
    raw='''proxies:\n- name: V\n  type: vless\n  server: v.example.com\n  port: 443\n  uuid: 11111111-2222-3333-4444-555555555555\n  network: ws\n  tls: true\n  ws-opts:\n    path: /ws\n'''
    c=ingest_content(raw).proxies[0]
    p=parse_uri(to_share_uri(c))
    assert p.host=="v.example.com" and p.params["path"]=="/ws"
