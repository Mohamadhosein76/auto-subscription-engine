from auto_subscription_engine.core.ingestion import ingest_content


def test_hiddify_import_deeplink_is_discovered_not_parsed_as_proxy():
    result = ingest_content("hiddify://import/https://example.org/sub#Example")
    assert result.proxies == []
    assert result.nested_sources == ["https://example.org/sub"]
