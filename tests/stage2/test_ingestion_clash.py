from auto_subscription_engine.core.ingestion import ingest_content
from auto_subscription_engine.core.models import OriginFormat


def test_clash_yaml_to_canonical_and_provider_discovery():
    raw='''
proxy-providers:
  upstream:
    type: http
    url: https://example.org/provider.yaml
proxies:
  - name: VL
    type: vless
    server: edge.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    network: ws
    tls: true
    sni: sni.example.com
    ws-opts:
      path: /edge
      headers:
        Host: cdn.example.com
  - name: TU
    type: tuic
    server: tuic.example.com
    port: 10443
    uuid: 22222222-3333-4444-5555-666666666666
    password: secret
    alpn: [h3]
    congestion-controller: bbr
    udp-relay-mode: native
'''
    r=ingest_content(raw,source="clash")
    assert r.detected_format is OriginFormat.CLASH_YAML
    assert [p.protocol for p in r.proxies]==["vless","tuic"]
    vl=r.proxies[0]
    assert vl.transport.kind=="ws" and vl.transport.path=="/edge"
    assert vl.transport.host=="cdn.example.com"
    assert vl.tls.server_name=="sni.example.com"
    tu=r.proxies[1]
    assert tu.auth.get("password")=="secret"
    assert tu.options["congestion_control"]=="bbr"
    assert r.nested_sources==["https://example.org/provider.yaml"]
