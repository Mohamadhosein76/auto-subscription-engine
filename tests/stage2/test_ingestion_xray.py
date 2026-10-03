import json
from auto_subscription_engine.core.ingestion import ingest_content
from auto_subscription_engine.core.models import OriginFormat


def test_xray_json_expands_vnext_users():
    raw=json.dumps({"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{
      "address":"x.example.com","port":443,"users":[
        {"id":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision"},
        {"id":"22222222-3333-4444-5555-666666666666"}
      ]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"s.example.com","alpn":["h2","http/1.1"]},"wsSettings":{"path":"/ws","headers":{"Host":"cdn.example.com"}}}}]})
    r=ingest_content(raw)
    assert r.detected_format is OriginFormat.XRAY_JSON
    assert len(r.proxies)==2
    assert all(p.protocol=="vless" for p in r.proxies)
    assert r.proxies[0].transport.kind=="ws"
    assert r.proxies[0].tls.server_name=="s.example.com"
    assert r.proxies[0].options["flow"]=="xtls-rprx-vision"
