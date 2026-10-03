# Stage 5 — Verification Engine v2

Stage 5 replaces the old package-root TCP/proxy-test stack with one authoritative subsystem:

```text
src/auto_subscription_engine/core/verification/
├── __init__.py
├── engine.py      # facade used by the live pipeline
├── policy.py      # bounded verification policy + target definitions
├── models.py      # credential-free result models + latency statistics
├── preflight.py   # DNS/address visibility + TCP diagnostics
├── http.py        # HTTP CONNECT + TLS + optional body validation
└── runtime.py     # real sing-box process + repeated application probes
```

The replaced `livemodels.py`, `tcpcheck.py`, and `proxytest.py` modules are deleted. Production code
and tests import the central subsystem directly.

## Why Stage 5 exists

The old pipeline had several correctness gaps:

1. A hostname was resolved by the GitHub runner and that IP was forced into sing-box for the runtime
   test, while the published client URI still contained the hostname. A node could therefore pass the
   CI test but fail on a user network whose DNS resolves the hostname differently.
2. `proxy.min_success_ratio` existed in configuration but the old `ProxyResult.passed` property only
   required **one successful HTTP probe**. Tightening the configured ratio did not actually tighten the
   LIVE verdict.
3. UDP-native protocols such as Hysteria2 could be discarded by a TCP gate even though TCP reachability
   is not the relevant transport truth.
4. A single successful request was too weak to distinguish a stable proxy from a transient/flaky one.
5. IPv4/IPv6 endpoint observations were collapsed to the first resolver answer instead of being kept as
   explicit diagnostics.

## Verification model

### 1. Endpoint preflight

Preflight is intentionally **not** the LIVE verdict.

For TCP-oriented protocols it:

- resolves all bounded A/AAAA candidates returned by the system resolver;
- records IPv4/IPv6 attempts independently;
- measures successful connect latency;
- classifies DNS, timeout, refused and other network failures;
- keeps a bounded best/selected address for diagnostics and geolocation.

For UDP-native protocols (`hysteria2`, and future live-enabled `tuic`) it resolves addresses but does
**not** require a TCP socket to open. Runtime core verification is the transport truth.

### 2. Native hostname runtime verification

Hostname configs are now passed to sing-box with the original hostname. The preflight resolver result
is not forced into the core.

A Stage 4 direct-IP variant is a separate canonical config whose `host` is already an IP while its
SNI/HTTP Host/Reality identity is preserved. That variant is therefore tested as a genuine IP-pinned
config.

This distinction is also carried into `live_nodes.json`:

- `resolved_ip` is populated only for genuine direct-IP configs;
- `preflight_resolved_ip` records the runner's diagnostic resolution for hostname configs.

Downstream Security and Compatibility stages therefore no longer receive the GitHub runner's DNS answer
as a forced runtime override for hostname nodes.

### 3. Repeated application-layer quorum

A runtime PASS requires the real core to start and repeated required targets to satisfy **all** of:

- minimum successful probe count;
- minimum aggregate success ratio;
- minimum per-round success ratio.

Production defaults use two rounds over three required destinations. A fourth tunneled DoH request is
an optional diagnostic and does not decide LIVE by itself.

This closes the previous `any(probe.ok)` bug.

### 4. TLS/content validation

HTTPS test targets use normal certificate verification (`ssl.create_default_context`). Optional expected
body substrings validate that a 200 response is actually the expected application response, not a captive
portal or arbitrary interception page.

TLS/Reality protocol handshakes themselves are exercised by the real sing-box outbound before the local
HTTP tunnel can succeed; no synthetic TLS preflight is treated as stronger evidence than the core.

### 5. Stability telemetry

Every runtime result records:

- success count;
- aggregate success ratio;
- per-round success ratios;
- p50 proxy latency;
- p95 proxy latency;
- simple latency jitter;
- failure-category aggregation.

The public metadata keeps the original stable keys for backward compatibility and adds a nested
`verification` object for the new evidence.

## Production policy

`config/testing.yaml -> verification` controls:

- endpoint connect timeout;
- preflight/runtime concurrency;
- maximum addresses inspected per node;
- core startup timeout;
- application probe timeout;
- repetition count;
- aggregate and per-round quorum;
- soft runtime deadline;
- body read cap;
- required and optional verification targets.

Runtime and candidate budgets remain bounded. Stage 6 now supplies the adaptive persistent candidate scheduler;
Stage 5 only makes each individual verification decision trustworthy.

## Compatibility contract

Public legacy metrics remain available (`tcp_*`, `proxy_*`) so publisher/monitoring consumers do not
break. Stage 5 additionally emits `preflight_*` and `runtime_*` metrics. The values now describe the new
central verification stages.

## Verification performed in this stage

Offline/local tests exercise:

- TCP endpoint success/failure classification;
- IPv4 + IPv6 address observations;
- UDP-native bypass of the meaningless TCP gate;
- process startup/cleanup;
- credential absence from process arguments;
- real HTTP CONNECT relay through a fake local core;
- TLS/application response status handling;
- response-body validation;
- aggregate quorum enforcement;
- per-round stability quorum enforcement;
- optional probe semantics;
- native hostname runtime behaviour (no resolver-IP override);
- direct-IP runtime behaviour;
- deadline exclusions;
- public-output metadata semantics;
- central-source-tree deletion guards.

No claim is made that this restricted container can prove real Internet/operator reachability. Stage 8
adds operator-local probe agents; Stage 5 provides the verification contract those probes will execute.

## Final verification snapshot

- full pytest suite: **644 passed / 0 failed**
- Python compileall: **PASS**
- `verify-publish --public-dir public`: **PASS**
- config/workflow YAML parse: **PASS**
- `git diff --check`: **PASS**
- Stage 4 vs Stage 5 structural fixture: **BYTE IDENTICAL** for plain + Base64 outputs
- structural plain SHA-256: `b64efd2293c33fdf5e4c84d5dfb7d55b7a68f1a699301b0722ee9abb333c1e6f`

Stage 5 deliberately does not claim operator-local Internet verification from this restricted container.
