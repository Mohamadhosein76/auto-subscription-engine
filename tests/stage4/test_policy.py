from auto_subscription_engine.core.network import load_ip_hunter_policy


def test_policy_loads_bounded_configuration(tmp_path):
    path = tmp_path / "ip_hunter.yaml"
    path.write_text(
        """
enabled: true
resolution:
  system: false
  doh_resolvers:
    - name: custom
      url: https://dns.example/resolve
      timeout_seconds: 2
variants:
  include_ipv4: true
  include_ipv6: false
  prefer_ipv4: true
history:
  include_recent: true
  candidate_ttl_days: 3
limits:
  concurrency: 999
  max_hostnames_per_run: 50
  max_variants_total: 25
  max_variants_per_node: 2
""",
        encoding="utf-8",
    )
    policy = load_ip_hunter_policy(path)
    assert policy.enabled
    assert policy.concurrency == 128
    assert policy.include_ipv6 is False
    assert policy.history_candidate_ttl_days == 3
    assert policy.max_variants_total == 25
    assert policy.doh_resolvers == (("custom", "https://dns.example/resolve", 2.0),)
