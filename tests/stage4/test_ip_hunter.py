from dataclasses import dataclass

from auto_subscription_engine.core.ingestion import ingest_content
from auto_subscription_engine.core.network import (
    DnsHistoryStore,
    IpHunterPolicy,
    ResolverAnswer,
    StaticIpHunter,
)
from auto_subscription_engine.core.serialization import to_share_uri


@dataclass
class FakeResolver:
    name: str
    answers: dict[str, tuple[str, ...]]

    def resolve(self, host: str) -> ResolverAnswer:
        return ResolverAnswer(self.name, self.answers.get(host, ()))


def _proxy(uri: str):
    result = ingest_content(uri)
    assert not result.issues
    assert len(result.proxies) == 1
    return result.proxies[0]


def _policy(**overrides):
    values = dict(
        enabled=True,
        concurrency=2,
        max_hostnames_per_run=20,
        max_variants_total=20,
        max_variants_per_node=8,
        include_ipv4=True,
        include_ipv6=True,
        prefer_ipv4=True,
        preserve_hostname_as_sni=True,
        preserve_http_host=True,
        include_history=True,
        history_candidate_ttl_days=7,
        history_retention_days=30,
        history_max_hosts=100,
        history_max_ips_per_host=10,
        use_system_resolver=False,
        doh_resolvers=(),
    )
    values.update(overrides)
    return IpHunterPolicy(**values)


def test_hunter_creates_ipv4_ipv6_variants_and_filters_non_public(tmp_path):
    proxy = _proxy(
        "vless://11111111-1111-1111-1111-111111111111@edge.example.com:443"
        "?security=tls&type=ws#edge"
    )
    resolver = FakeResolver(
        "test",
        {
            "edge.example.com": (
                "8.8.8.8",
                "2001:4860:4860::8888",
                "10.0.0.1",
            )
        },
    )
    hunter = StaticIpHunter(
        policy=_policy(),
        history=DnsHistoryStore(tmp_path / "history.json"),
        resolvers=[resolver],
    )
    result = hunter.hunt([proxy])

    assert {item.host for item in result.variants} == {
        "8.8.8.8",
        "2001:4860:4860::8888",
    }
    assert result.skipped_non_public == 1
    assert result.current_variants == 2
    assert result.history_variants == 0
    for variant in result.variants:
        assert variant.tls.server_name == "edge.example.com"
        assert variant.transport.host == "edge.example.com"
        assert variant.extra_fields["ip_hunter"]["original_host"] == "edge.example.com"
        assert variant.raw == ""
        rendered = to_share_uri(variant)
        assert "sni=edge.example.com" in rendered
        assert "host=edge.example.com" in rendered


def test_hunter_preserves_explicit_sni_host_and_reality(tmp_path):
    proxy = _proxy(
        "vless://11111111-1111-1111-1111-111111111111@edge.example.com:443"
        "?security=reality&type=ws&sni=front.example.net&host=ws.example.net"
        "&pbk=PUBLICKEY&sid=abcd&spx=%2Fprobe#edge"
    )
    hunter = StaticIpHunter(
        policy=_policy(),
        history=DnsHistoryStore(tmp_path / "history.json"),
        resolvers=[FakeResolver("test", {"edge.example.com": ("8.8.8.8",)})],
    )
    variant = hunter.hunt([proxy]).variants[0]
    assert variant.tls.server_name == "front.example.net"
    assert variant.transport.host == "ws.example.net"
    assert variant.tls.reality_public_key == "PUBLICKEY"
    assert variant.tls.reality_short_id == "abcd"
    assert variant.tls.reality_spider_x == "/probe"
    rendered = to_share_uri(variant)
    assert "sni=front.example.net" in rendered
    assert "host=ws.example.net" in rendered
    assert "pbk=PUBLICKEY" in rendered
    assert "sid=abcd" in rendered
    assert "spx=/probe" in rendered


def test_hunter_reuses_recent_history_when_dns_temporarily_empty(tmp_path):
    history_path = tmp_path / "history.json"
    proxy = _proxy(
        "trojan://secret@edge.example.com:443?security=tls#edge"
    )
    first = StaticIpHunter(
        policy=_policy(),
        history=DnsHistoryStore(history_path),
        resolvers=[FakeResolver("test", {"edge.example.com": ("8.8.8.8",)})],
    )
    assert first.hunt([proxy]).current_variants == 1

    second = StaticIpHunter(
        policy=_policy(),
        history=DnsHistoryStore.load(history_path),
        resolvers=[FakeResolver("test", {"edge.example.com": ()})],
    )
    result = second.hunt([proxy])
    assert result.unresolved_hosts == 1
    assert result.current_variants == 0
    assert result.history_variants == 1
    assert result.variants[0].host == "8.8.8.8"
    assert result.variants[0].extra_fields["ip_hunter"]["candidate_origin"] == "dns_history"


def test_hunter_never_expands_an_existing_direct_ip(tmp_path):
    proxy = _proxy(
        "vless://11111111-1111-1111-1111-111111111111@8.8.8.8:443?security=tls"
    )
    hunter = StaticIpHunter(
        policy=_policy(),
        history=DnsHistoryStore(tmp_path / "history.json"),
        resolvers=[FakeResolver("test", {})],
    )
    result = hunter.hunt([proxy])
    assert result.direct_inputs == 1
    assert result.variants == []
