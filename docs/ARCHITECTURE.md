# Auto Subscription Engine — Architecture

ASE 1.0 is an evidence-driven pipeline for discovering public proxy configurations, normalizing them into one canonical model, testing them with real pinned proxy cores, scoring the resulting evidence and publishing guarded subscription feeds. The production source of truth is the single tree at `src/auto_subscription_engine/core/`; package-root Python is limited to CLI/package entry points.

![ASE architecture](../.github/assets/ase-architecture.svg)

## Design invariants

1. **One implementation per responsibility.** Replaced root modules are deleted rather than retained as compatibility shims.
2. **Canonical first.** URI, Base64, Clash/Mihomo YAML, sing-box JSON and Xray-style JSON inputs converge on the same canonical proxy model before downstream decisions.
3. **Evidence is typed by context.** Global, client, operator, reliability, freshness and security evidence are separate dimensions. Missing evidence is `unknown`, not an implicit failure.
4. **Runtime truth beats syntax.** Parsing or core config acceptance does not make a node LIVE. Required application traffic must traverse a compatible pinned core and satisfy repeated quorum.
5. **Hostname fidelity.** A hostname config is runtime-tested as a hostname. Resolver IPs are diagnostic unless ASE explicitly creates a separate direct-IP variant.
6. **No blind scanning.** Static-IP candidates originate only from A/AAAA observations for already-discovered proxy hostnames.
7. **Security is not weakened for volume.** Security filtering and hard publication guards can reduce output; they are not silently bypassed to increase feed size.
8. **Last-known-good wins over partial publication.** State corruption, verification failure or release-gate failure stops promotion and preserves the previous public tree.
9. **Credentials are transient.** Public URI files may contain proxy credentials by definition; persistent intelligence, manifests, scorecards, health reports and operator state must not.
10. **Operator claims require physical evidence.** GitHub-hosted runner results are never presented as MCI/Irancell/Rightel/fixed-network compatibility.

## End-to-end data flow

```text
Configured roots
  -> bounded recursive Discovery + Source Intelligence
  -> Canonical Ingestion / Protocol Registry
  -> Structural validation + logical deduplication
  -> DNS observation + Static-IP Hunter
  -> Persistent Smart Scheduler
  -> Endpoint Preflight (diagnostic)
  -> Multi-Core Runtime Verification (decisive)
  -> Reliability / latency / country evidence
  -> Security Intelligence + Policy
  -> Multi-Client compatibility evidence
  -> Multidimensional Scoring
  -> Score-Aware Feed Engine
  -> Feed/Public/Production verifiers
  -> Transactional staging + atomic public promotion
```

## Central source tree

| Domain | Path | Responsibility |
|---|---|---|
| Canonical models | `core/models/` | schema, validation, fingerprints, conversion, deduplication |
| Protocols | `core/protocols/` | VLESS, VMess, Trojan, Shadowsocks, Hysteria2 and TUIC parsing |
| Ingestion | `core/ingestion/` | text/container decoding and structured input adapters |
| Serialization | `core/serialization/` | canonical proxy to interoperable share URI |
| Discovery | `core/discovery/` | source catalog, recursive fetch, source intelligence, quarantine |
| Network | `core/network/` | address policy, DNS history, geolocation, direct-IP expansion |
| Scheduling | `core/scheduling/` | persistent candidate intelligence, due times, exploration/recovery lanes |
| Verification | `core/verification/` | preflight evidence and repeated application-layer runtime verification |
| Clients | `core/clients/` | pinned core registry/install, lifecycle, native builders/exporters, compatibility evidence |
| Security | `core/security/` | reputation feeds, ASN/DNS/TLS/content evidence and security policy |
| Operator Probe | `core/operator_probe/` | signed jobs/results, persistent physical-network evidence, Go supervisor |
| Scoring | `core/scoring/` | contextual scorecards and explicit unknown-vs-fail semantics |
| Feeds | `core/feeds/` | sole owner of final client/profile/network/operator membership |
| Hardening | `core/hardening/` | durable state, crash-recoverable publication, production release gate |
| Orchestration | `core/orchestration/` | structural/live pipeline composition and output verification |
| Utilities | `core/utils/` | credential-safe identity/redaction and bounded helpers |

## Discovery and source intelligence

![Discovery and Static-IP](../.github/assets/ase-discovery-static-ip.svg)

`core/discovery/` starts from `config/sources.yaml`, validates HTTP(S) roots, fetches sources concurrently but processes results in deterministic scheduler order, extracts nested source URLs within depth/fan-out limits and records credential-free quality telemetry in `data/discovery.json`.

Source quality controls ordering and adaptive scheduling; repeated source failures cause bounded temporary quarantine. Successful fetches clear quarantine. Network/source failure is isolated to that source rather than aborting the whole graph.

## Static-IP Hunter

`core/network/` observes DNS A and AAAA answers through configured resolvers and stores bounded history in `data/ip_history.json`. It can derive direct-IP variants from those observations while preserving identity-bearing parameters such as TLS SNI, HTTP Host, Reality fields, authentication and path. Private, reserved and otherwise non-global addresses are rejected.

The hunter does **not** scan arbitrary subnets, CDN ranges or the public Internet. A direct-IP variant exists only because a discovered hostname yielded that IP now or in bounded recent DNS history.

## Scheduler

`core/scheduling/` replaces fixed-prefix sampling with persistent candidate intelligence. Every candidate is tracked by fingerprint across runs and assigned to lanes such as exploration, recovery, flaky, healthy and stale. Budgets are ceilings; they do not imply that the first N configs repeatedly consume all verification capacity.

Important properties include never-tested rotation, exponential recovery backoff, direct-IP reservation, source-quality soft caps, protocol fairness, preflight-to-runtime promotion and persisted due times in `data/history.json`.

## Verification and multi-client runtime

![Verification and Multi-Client](../.github/assets/ase-verification-multiclient.svg)

Preflight DNS/TCP/TLS evidence is diagnostic. A candidate becomes LIVE only after a compatible pinned core accepts the config, starts successfully and carries repeated required HTTP/HTTPS traffic through the tunnel. ASE records success ratio, repeated-round evidence and latency statistics such as p50/p95/jitter.

The core/client registry currently maps runtime evidence to:

| Client/feed family | Runtime core | Native artifact |
|---|---|---|
| v2rayNG family | Xray-core | URI feed |
| Hiddify family | Hiddify-Core | URI feed |
| NekoBox family | sing-box | URI feed |
| native sing-box | sing-box | `singbox.json` |
| Mihomo / Clash.Meta family | Mihomo | `mihomo.yaml` |

This means ASE has runtime/core evidence and serializers for those feed families. It does **not** claim that every GUI version/device combination has been manually validated.

Shadowrocket, Stash, Loon, Surge and Quantumult X remain intentionally non-publishable until ASE owns native serialization plus appropriate validation evidence.

## Security intelligence

Security evaluates the already-LIVE pool using official/key-free reputation feeds, ASN intelligence, DNS checks, TLS verification and bounded HTTPS content-integrity probes. Decisions can be `ALLOW`, `ALLOW_WITH_WARNINGS`, `QUARANTINE` or `BLOCK`.

Normal certificate verification and hostname verification are never disabled. Network/hosting ASN identity is metadata, not a generic malice label; explicit policy and evidence decide publication.

## Operator Probe system

![Operator topology](../.github/assets/ase-operator-probe-topology.svg)

A self-hosted runner physically attached to a target network receives an expiring HMAC-SHA256 signed probe job, runs the central Python verification/client runtime under the Go supervisor and returns a signed credential-free result. Replay protection and result freshness live in `data/operator_probes.json`.

The Go agent intentionally does **not** reimplement proxy protocols. It verifies envelopes, launches the fixed central worker, enforces result hygiene and signs the result.

## Scoring

ASE keeps contextual scores separate:

- **Global:** general verified quality.
- **Client:** evidence for one mapped runtime/core/client context.
- **Operator:** only when actual operator probe evidence exists.
- **Reliability:** historical success behavior.
- **Freshness:** age of relevant evidence.
- **Security:** security decision/evidence quality.

Operator score stays `null` without operator evidence. A client dimension can be `null` when not evaluated/unavailable; a real measured failure may legitimately score `0`.

## Feed Engine

`core/feeds/` is the only final feed-membership authority. It consumes verified candidates plus scorecards and builds client feeds, quality profiles, network feeds and fresh-evidence-only operator feeds. Compatibility stages provide evidence but no longer decide final membership.

Native sing-box/Mihomo output keeps the canonical hostname unless the canonical candidate itself is a direct-IP variant.

## Production hardening

![Scoring, feeds and publication](../.github/assets/ase-scoring-feed-publish.svg)

Persistent JSON state uses same-filesystem temporary writes, file `fsync`, atomic `os.replace`, best-effort directory `fsync` and `.bak` last-known-good recovery. Corrupt primary + valid backup restores the backup; unrecoverable corruption fails closed instead of silently resetting intelligence.

Publication recovers interrupted `public -> old -> staging -> public` rename windows. Promotion requires same-filesystem atomicity, then public/feed/score/production verifiers run before any auto-commit/push path.

The release gate also rejects tracked caches/binaries/backups, stale staging artifacts, unreadable/oversized state and sensitive data in credential-free stores.

## Public-contract boundary

The following legacy paths are locked for backward compatibility unless a future explicit breaking decision changes them:

```text
public/subscription.txt
public/subscription_base64.txt
public/clients/v2rayng.txt
public/clients/hiddify.txt
public/clients/nekobox.txt
public/clients/mihomo.yaml
public/clients/universal.txt
```

The main legacy subscription remains the score-ranked universal feed after successful publication.
