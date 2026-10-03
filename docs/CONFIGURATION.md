# Configuration Reference

ASE keeps operational configuration in tracked YAML. These files are non-secret; credentials/tokens belong in environment variables or GitHub secrets, never YAML. Stage 12 audited every current key against the production loaders/consumers and removed hard-coded bypasses for `compatibility.min_universal_nodes` and `compatibility.mobile_safe.udp_share_cap` by wiring those settings into the real implementation.

## `config/sources.yaml`

`source` entries seed the bounded Discovery graph. Allowed entry fields are validated; unknown fields are rejected.

| Field | Default | Meaning |
|---|---:|---|
| `name` | required | unique human-readable source name |
| `url` | required | HTTP(S) source URL; private/local/credential-bearing source URLs are rejected by source validation |
| `enabled` | `true` | include/exclude the root without deleting it |
| `priority` | `50` | integer `0..100` used as initial ordering signal |
| `tags` | `[]` | unique string labels for source metadata |

Community source availability is volatile. A configured source is not a promise that the upstream endpoint is currently healthy.

## `config/discovery.yaml`

| Key | Default | Meaning |
|---|---:|---|
| `discovery.max_depth` | `2` | maximum recursive nested-source depth; roots are depth 0 |
| `discovery.max_sources` | `64` | absolute root+nested sources processed in one run |
| `discovery.max_nested_per_source` | `16` | per-source nested-provider fan-out cap |
| `discovery.max_total_proxies` | `50000` | canonical candidate memory/work ceiling before connectivity stages |
| `discovery.fetch_concurrency` | `8` | concurrent source fetch worker ceiling; result processing remains deterministic |
| `discovery.quarantine_after_failures` | `3` | consecutive failed fetches before temporary source quarantine |
| `discovery.quarantine_base_minutes` | `30` | initial quarantine duration |
| `discovery.quarantine_max_hours` | `24` | exponential quarantine ceiling |

## `config/ip_hunter.yaml`

### Enable/resolution

| Key | Default | Meaning |
|---|---:|---|
| `enabled` | `true` | enable DNS-derived static/direct-IP expansion |
| `resolution.system` | `true` | include the system resolver |
| `resolution.doh_resolvers[]` | Google DoH | additional explicit DoH resolver definitions |
| `resolution.doh_resolvers[].name` | required-ish | resolver label stored in evidence |
| `resolution.doh_resolvers[].url` | required | DoH endpoint |
| `resolution.doh_resolvers[].timeout_seconds` | `4.0` | per-resolver timeout; loader floors at 0.1s |

### Variant semantics

| Key | Default | Meaning |
|---|---:|---|
| `variants.include_ipv4` | `true` | allow global IPv4 direct-IP candidates |
| `variants.include_ipv6` | `true` | allow global IPv6 direct-IP candidates |
| `variants.prefer_ipv4` | `true` | deterministic ordering preference, not a ban on IPv6 |
| `variants.preserve_hostname_as_sni` | `true` | materialize/preserve TLS identity before endpoint replacement |
| `variants.preserve_http_host` | `true` | preserve HTTP/WebSocket/etc. Host identity where relevant |

### DNS history

| Key | Default | Meaning |
|---|---:|---|
| `history.include_recent` | `true` | include bounded recent DNS observations for the same discovered hostname |
| `history.candidate_ttl_days` | `7` | age window in which historical IPs may become candidates |
| `history.retention_days` | `30` | retained DNS evidence horizon |
| `history.max_hosts` | `10000` | persistent host bound |
| `history.max_ips_per_host` | `24` | persistent IP observations per hostname bound |

### Work limits

| Key | Default | Meaning |
|---|---:|---|
| `limits.concurrency` | `32` | DNS/static-IP worker ceiling; loader caps at 128 |
| `limits.max_hostnames_per_run` | `600` | distinct discovered hostnames resolved per run |
| `limits.max_variants_total` | `400` | total generated direct-IP candidates |
| `limits.max_variants_per_node` | `4` | variants from one canonical node |

None of these settings enable subnet or Internet scanning.

## `config/feeds.yaml`

| Key | Default | Meaning |
|---|---:|---|
| `feeds.max_nodes_per_feed` | `200` | hard size ceiling for each selected feed |
| `feeds.min_client_score` | `50` | client score floor before fallback logic |
| `feeds.min_operator_score` | `65` | operator-context score floor |
| `feeds.min_operator_confidence` | `50` | operator evidence confidence floor |
| `feeds.require_fresh_operator_evidence` | `true` | require operator dimension `fresh == true` |
| `feeds.recommended_min_global` | `60` | Recommended profile global-score threshold |
| `feeds.secure_min_global` | `50` | Secure profile global-score threshold |
| `feeds.secure_min_security` | `80` | Secure profile Security-score threshold |
| `feeds.min_fallback_nodes` | `3` | verified fallback floor when a filtered pool is too small |
| `feeds.per_asn_limit` | `8` | diversity cap per announcing ASN |
| `feeds.per_prefix_limit` | `4` | diversity cap per endpoint prefix |
| `feeds.per_source_soft_limit` | `0.50` | soft share ceiling for one source; relaxed only for verified fallback needs |

All score/confidence thresholds validate within `0..100`.

## `config/operator_probes.yaml`

`schema_version` is a file-format marker, not an operational tuning knob.

### Profile fields

| Field | Default | Meaning |
|---|---:|---|
| `profiles.<key>.display_name` | profile key | UI/report label |
| `profiles.<key>.network_type` | `unknown` | descriptive network category (`mobile`, `fixed`, custom) |
| `profiles.<key>.runner_label` | `ase-<key>` | exact expected self-hosted runner label |
| `profiles.<key>.enabled` | `true` | allow signed jobs for the profile |

### Probe policy

| Key | Default | Meaning |
|---|---:|---|
| `policy.job_ttl_minutes` | `30` | signed job validity window |
| `policy.max_candidates_per_job` | `100` | candidate cap per physical probe job |
| `policy.result_max_age_minutes` | `180` | oldest signed result accepted for ingest |
| `policy.stale_after_minutes` | `120` | age after which operator evidence is no longer fresh |
| `policy.history_retention_days` | `30` | operator evidence retention horizon |
| `policy.max_nodes` | `50000` | persistent per-node state bound |
| `policy.processed_result_ids` | `2000` | replay-protection result-ID memory bound |

## `config/testing.yaml`

This file combines runtime verification, scheduling, scoring, security, compatibility and publication policy. It is intentionally public and non-sensitive.

### Pinned proxy cores

`singbox.*` configures the pinned sing-box archive used by the central registry. `cores.<xray|hiddify|mihomo>.*` configures the other pinned runtimes.

| Field | Meaning |
|---|---|
| `version` | exact upstream release version |
| `archive_sha256` | required archive digest checked before extraction |
| `url_template` | official release download URL template |
| `archive_binary_path` / `binary_path_in_archive` | safe archive member to extract |
| `format` | supported archive format (`zip`, `tar.gz`, `gz`) |

Floating `latest` core versions are intentionally not used.

### `verification.*`

| Key | Default | Meaning |
|---|---:|---|
| `connect_timeout_seconds` | `3.0` | endpoint-preflight connect timeout |
| `preflight_concurrency` | `200` | preflight worker ceiling |
| `max_addresses_per_node` | `6` | resolver-address diagnostics bound per node |
| `runtime_concurrency` | `10` | concurrent real-core runtime tests |
| `startup_timeout_seconds` | `5.0` | core readiness deadline |
| `http_timeout_seconds` | `8.0` | per tunneled HTTP(S) request deadline |
| `repetitions` | `2` | required target repetition count |
| `min_success_ratio` | `0.66` | minimum success ratio across required probes |
| `min_success_count` | `4` | absolute required-probe success floor |
| `min_round_success_ratio` | `0.5` | per-round success-ratio floor |
| `soft_deadline_seconds` | `600.0` | bounded runtime-stage soft deadline |
| `max_body_bytes` | `65536` | tunneled response body cap |

Each `verification.targets[]` item accepts:

| Field | Meaning |
|---|---|
| `url` | HTTP(S) target URL |
| `expect_status` | accepted status-code list |
| `expect_substring` | optional content-integrity substring |
| `kind` | e.g. `egress` or diagnostic `doh` |
| `required` | optional; `false` makes the probe diagnostic rather than quorum-deciding |

### `scheduler.*`

| Key | Default | Meaning |
|---|---:|---|
| `preflight_budget` | `1500` | max candidates receiving preflight work per run |
| `runtime_budget` | `400` | max candidates receiving real runtime work per run |
| `exploration_share` | `0.35` | budget share reserved for never/under-tested exploration |
| `recovery_share` | `0.20` | share reserved for due recovery candidates |
| `direct_ip_share` | `0.15` | direct-IP reservation share |
| `source_base_share` | `0.15` | baseline per-source fairness signal |
| `source_quality_bonus_share` | `0.20` | extra budget share influenced by learned source quality |
| `source_quality_weight` | `20.0` | quality contribution to scheduler priority |
| `healthy_retest_minutes` | `180` | healthy candidate retest cadence |
| `flaky_retest_minutes` | `45` | flaky candidate retest cadence |
| `exploration_retry_minutes` | `60` | never/under-tested retry cadence |
| `recovery_base_minutes` | `30` | first recovery backoff |
| `recovery_max_hours` | `12` | exponential recovery backoff ceiling |
| `stale_after_hours` | `24` | evidence age considered stale |
| `flaky_success_rate` | `0.75` | historical rate below which a candidate is flaky |
| `direct_ip_bonus` | `12.0` | priority bonus for direct-IP candidates |
| `preflight_latency_bonus` | `10.0` | preflight latency contribution to runtime promotion |
| `allow_early_fill` | `true` | allow safe budget fill when strict lane quotas leave unused capacity |

Budgets are ceilings, not stable prefixes. Persistent history prevents the same early-list candidates from monopolizing all work.

### `geo.*`

| Key | Default | Meaning |
|---|---:|---|
| `batch_url` | ip-api batch | key-free batch geolocation endpoint |
| `single_url` | ip-api single | fallback URL template |
| `timeout_seconds` | `5.0` | request timeout |
| `batch_size` | `100` | IPs per batch |
| `batch_rate_per_minute` | `15` | request pacing ceiling |
| `max_lookups` | `1000` | geolocation work cap per run |

Country lookup is enrichment; failure degrades to `UNKNOWN` rather than changing connectivity truth.

### `scoring.*`

Weight groups:

- `preselection_weights.connectivity|latency|reliability|stability`
- `global_weights.connectivity|latency|reliability|freshness|security`
- `operator_weights.connectivity|reliability|latency|freshness`
- `client_weights.runtime|reliability|latency`

Other knobs:

| Key | Default | Meaning |
|---|---:|---|
| `latency_min_ms` | `150.0` | latency score best anchor |
| `latency_max_ms` | `3000.0` | latency score worst anchor |
| `min_history_samples` | `3` | sample floor for mature reliability confidence |
| `freshness_full_minutes` | `60` | evidence age retaining full freshness score |
| `freshness_zero_minutes` | `1440` | age at which freshness contribution reaches zero |

Weights are contextual. Operator/client dimensions do not silently modify the Global score.

### `selection.*`, `history.*`, `publish.*`

| Key | Default | Meaning |
|---|---:|---|
| `selection.max_live_nodes` | `300` | legacy selected-LIVE ceiling |
| `selection.per_host_limit` | `3` | legacy host diversity bound |
| `history.retention_days` | `30` | reliability history horizon |
| `history.max_entries` | `50000` | persistent history entry cap |
| `publish.min_live_nodes` | `5` | minimum healthy set required for promotion |
| `publish.max_drop_ratio` | `0.8` | maximum allowed collapse versus previous healthy public set |

### `security.*`

| Key | Default | Meaning |
|---|---:|---|
| `enabled` | `true` | enable Security Intelligence Layer |
| `feeds.spamhaus_drop` | official DROP URL | IPv4 reputation feed |
| `feeds.spamhaus_dropv6` | official DROPv6 URL | IPv6 reputation feed |
| `feeds.spamhaus_asndrop` | official ASN-DROP JSON | malicious ASN evidence source |
| `feeds.feodo_recommended` | official Feodo recommended JSON | active botnet C2 evidence source |
| `feeds.refresh_interval_hours` | `24` | minimum refresh interval |
| `feeds.max_age_hours` | `96` | stale-cache ceiling before fail-closed behavior |
| `feeds.timeout_seconds` | `20.0` | feed request timeout |
| `feeds.retries` | `2` | bounded feed retries |
| `feeds.max_bytes` | `5242880` | feed response-size cap |
| `asn.whois_host` | Team Cymru | primary ASN source |
| `asn.whois_port` | `43` | WHOIS port |
| `asn.fallback_url` | RIPEstat | key-free fallback |
| `asn.timeout_seconds` | `10.0` | ASN request timeout |
| `asn.retries` | `1` | ASN retry count |
| `asn.concurrency` | `4` | fallback lookup concurrency |
| `asn.cache_ttl_hours` | `336` | ASN cache validity |
| `asn.max_cache_entries` | `20000` | ASN cache bound |
| `asn.max_lookups_per_run` | `5000` | ASN network-work cap |
| `dns.doh_url` | Google DNS | independent DoH check endpoint |
| `dns.timeout_seconds` | `5.0` | DNS security timeout |
| `dns.concurrency` | `8` | DNS security concurrency |
| `tls.timeout_seconds` | `8.0` | tunneled TLS probe timeout |
| `content.timeout_seconds` | `8.0` | content probe timeout |
| `content.max_body_bytes` | `65536` | content body cap |
| `content.failure_threshold` | `2` | independent integrity failures required for anomaly evidence |
| `probe.concurrency` | `8` | security probe concurrency |
| `probe.startup_timeout_seconds` | `5.0` | compatible-core startup deadline |
| `policy.max_nodes_per_asn` | `10` | publication concentration cap; not a malice label |
| `policy.quarantine_on_incomplete` | `false` | whether inconclusive security checks force quarantine |
| `policy.forbidden_asns` | `[13335, 209242]` | explicit project-policy endpoint ASN blocklist |
| `policy.require_asn_for_publish` | `true` | require determined ASN before publication |
| `min_publishable_nodes` | `5` | fail-safe survivor floor for security-filtered publication |

Each `security.content.endpoints[]` item supports `url`, `expect_status`, `expect_substring` and the runtime integrity-check semantics implemented by the TLS/content probe.

### `compatibility.*`

| Key | Default | Meaning |
|---|---:|---|
| `enabled` | `true` | enable multi-core client evidence stage |
| `cores` | four central cores | runtime cores to test when available |
| `startup_timeout_seconds` | `8.0` | core startup deadline |
| `http_timeout_seconds` | `8.0` | compatibility tunnel request timeout |
| `concurrency_per_core` | `8` | bounded process/test concurrency for each core |
| `soft_deadline_seconds_per_core` | `420.0` | per-core stage deadline |
| `min_universal_nodes` | `1` | guarded publish floor for universal feed; now wired into `PublishOptions` |
| `min_feed_nodes` | `3` | diversity/fallback floor preventing hollowed feeds |
| `max_mobile_safe_nodes` | `50` | mobile-safe candidate feed cap |
| `diversity.per_asn_limit` | `8` | per-ASN feed diversity cap |
| `diversity.per_prefix_limit` | `4` | per-prefix cap |
| `diversity.per_host_limit` | `3` | per-host cap |
| `diversity.per_source_soft_limit` | `0.50` | soft source share cap |
| `mobile_safe.max_latency_ms` | `1500.0` | heuristic latency ceiling for mobile-safe candidates |
| `mobile_safe.udp_share_cap` | `0.20` | maximum UDP-native share in mobile-safe output; now consumed by the real selector |

Each `compatibility.test_urls[]` item supports `url`, `expect_status` and optional `expect_substring`. TLS certificate verification remains enabled.

## Secrets

No config file accepts or should contain a probe HMAC secret, GitHub token, private key or proxy management credential. Operator probe secrets are read from an environment variable (`ASE_OPERATOR_PROBE_SECRET` by default). GitHub Actions should source it from Environment/Repository Secrets.
