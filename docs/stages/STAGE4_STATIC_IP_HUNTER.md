# Stage 4 — Static-IP Hunter

Stage 4 adds bounded, DNS-derived direct-IP candidate generation without blind address-space scanning.
It is intentionally limited to hostnames already present in proxy configurations discovered by ASE.

## Central source tree

All new logic lives under:

```text
src/auto_subscription_engine/core/network/
├── __init__.py
├── address.py      # one host/IP classification source of truth
├── dns.py          # system + pluggable JSON DoH resolvers
├── history.py      # bounded credential-free DNS/IP history
├── ip_hunter.py    # domain -> direct-IP candidate engine
└── models.py       # resolution/hunter result models
```

The replaced package-root `netutil.py` implementation was deleted. Duplicate IP-literal helpers in
sing-box and compatibility classification were removed and migrated to `core/network`.
Security DNS checks now reuse the same central address/DNS primitives instead of carrying their own
copies.

## Candidate derivation

For each sampled canonical proxy whose endpoint is a hostname:

1. Resolve the hostname through the configured resolver set.
2. Keep only globally routable IPv4/IPv6 answers.
3. Record public answers in bounded `data/ip_history.json`.
4. Add recent historical IPs for the same hostname when enabled.
5. Build one independent canonical proxy variant per allowed address.
6. Recompute the logical fingerprint so every pinned address is tested independently.
7. Feed the generated variants into the existing TCP/runtime pipeline before Stage A.

Existing direct-IP configs are recognized and are never needlessly expanded.

## Identity preservation

Replacing `edge.example.com` with `8.8.8.8` must not silently change the logical upstream identity.
The hunter therefore:

- preserves explicit TLS/Reality SNI;
- materializes the original hostname as SNI when TLS/Reality relied on the endpoint hostname;
- preserves explicit WebSocket/HTTP/XHTTP Host values;
- materializes the original hostname as Host for HTTP-like transports when it was implicit;
- preserves Reality public key, short ID and spider-x;
- preserves UUID/password/authentication, path, service name, ALPN and fingerprint fields.

## DNS history

`data/ip_history.json` stores only hostname/address observations and resolver labels. It never stores
proxy credentials or complete share URIs.

History is bounded by:

- retention days;
- maximum host count;
- maximum IPs per host;
- candidate age TTL.

This lets ASE retry an IP that was recently attached to a proxy hostname even when the current DNS
answer rotates or temporarily disappears.

## Production policy

`config/ip_hunter.yaml` controls:

- system DNS enablement;
- independent DoH resolvers;
- IPv4/IPv6 inclusion and preference;
- SNI/Host preservation;
- DNS-history reuse;
- concurrency;
- per-run hostname and variant budgets.

The current production limits add at most 400 direct-IP variants per live run and at most four
variants per sampled node. Stage 6 now provides the history-aware scheduler that allocates bounded verification opportunities to these variants.

## Safety boundary

Stage 4 does **not** scan subnets, enumerate adjacent IPs, probe arbitrary address ranges, or infer
unrelated hosts. Candidates come only from DNS answers/history belonging to proxy endpoints already
present in discovered public configurations.

## Pipeline integration

The hourly workflow now runs the live command with:

```text
--ip-hunter-config config/ip_hunter.yaml
--ip-history data/ip_history.json
```

The DNS/IP history file is committed with the existing bounded intelligence state so observations
survive across runs.

## Verification

Stage 4 has dedicated tests for:

- public/bogon address classification;
- IPv4 and IPv6 candidate generation;
- private/reserved answer rejection;
- explicit and implicit SNI preservation;
- WebSocket/HTTP Host preservation;
- Reality public-key/short-ID/spider-x preservation;
- direct-IP input handling;
- current DNS vs recent-history variants;
- history retention/bounds;
- policy bounds;
- actual live-pipeline insertion before the TCP stage;
- central-source-tree cleanup.
