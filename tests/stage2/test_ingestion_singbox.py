import json
from auto_subscription_engine.core.ingestion import ingest_content
from auto_subscription_engine.core.models import OriginFormat


def test_singbox_json_to_canonical():
    raw=json.dumps({"outbounds":[
      {"type":"vless","tag":"vl","server":"v.example.com","server_port":443,
       "uuid":"11111111-2222-3333-4444-555555555555",
       "tls":{"enabled":True,"server_name":"s.example.com","reality":{"enabled":True,"public_key":"PK","short_id":"01"}},
       "transport":{"type":"grpc","service_name":"svc"}},
      {"type":"tuic","tag":"tu","server":"t.example.com","server_port":443,
       "uuid":"22222222-3333-4444-5555-666666666666","password":"pw",
       "congestion_control":"cubic","udp_relay_mode":"native","tls":{"enabled":True,"server_name":"t.example.com"}},
      {"type":"direct","tag":"direct"}
    ]})
    r=ingest_content(raw)
    assert r.detected_format is OriginFormat.SINGBOX_JSON
    assert [x.protocol for x in r.proxies]==["vless","tuic"]
    assert r.proxies[0].tls.mode=="reality"
    assert r.proxies[0].transport.service_name=="svc"
    assert r.proxies[1].auth.get("password")=="pw"


def test_base64_minified_singbox_json_is_detected():
    import base64
    raw=json.dumps({"outbounds":[{"type":"trojan","tag":"t","server":"t.example.com","server_port":443,"password":"pw","tls":{"enabled":True,"server_name":"t.example.com"}}]},separators=(",",":"))
    encoded=base64.b64encode(raw.encode()).decode()
    r=ingest_content(encoded)
    assert r.detected_format is OriginFormat.SINGBOX_JSON
    assert len(r.proxies)==1 and r.proxies[0].protocol=="trojan"
