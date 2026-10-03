from auto_subscription_engine.core.network import (
    canonicalize_host,
    classify_ip,
    ip_version,
    is_ip_literal,
    is_local_host,
    is_public_ip,
    is_valid_host_format,
)


def test_address_classification_is_central_and_strict():
    assert canonicalize_host("Example.COM.") == "example.com"
    assert canonicalize_host("2001:0db8::1") == "2001:db8::1"
    assert is_ip_literal("8.8.8.8")
    assert ip_version("2001:4860:4860::8888") == 6
    assert is_public_ip("8.8.8.8")
    assert not is_public_ip("10.0.0.1")
    assert classify_ip("100.64.0.1") != "public"
    assert is_local_host("localhost")
    assert is_local_host("192.168.1.1")
    assert is_valid_host_format("edge.example.com")
