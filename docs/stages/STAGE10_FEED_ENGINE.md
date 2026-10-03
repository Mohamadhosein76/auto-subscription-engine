# Stage 10 — Score-Aware Feed Engine

Stage 10 moves user-facing feed selection out of the compatibility stage and into one central `core/feeds/` subsystem. Compatibility now records evidence only; Scoring attaches the Stage-9 scorecard; Feed Engine is the only stage that decides which verified node enters which subscription.

## Central source tree

```text
src/auto_subscription_engine/core/feeds/
├── engine.py
├── models.py
├── policy.py
└── verify.py
```

Policy lives in `config/feeds.yaml`.

## Pipeline contract

```text
Security
  -> Multi-client compatibility evidence
  -> Stage-9 scorecards
  -> Stage-10 Feed Engine
  -> verify-feed
  -> guarded transactional publisher
```

Stage 7 no longer rewrites `live_subscription.txt` or creates final `clients/` / `networks/` artifacts. It leaves the full security-publishable URI set intact and enriches `live_nodes.json` with core compatibility and network-profile evidence. Stage 10 then consumes that full set plus scorecards.

## Feeds

### Stable client feeds

- `clients/universal.txt` — all-core intersection, score-ranked. The legacy main `subscription.txt` remains byte-equal to this feed after publish.
- `clients/v2rayng.txt` — Xray PASS + v2rayNG client score.
- `clients/hiddify.txt` — Hiddify-Core PASS + Hiddify score.
- `clients/nekobox.txt` — sing-box PASS + NekoBox score.
- `clients/singbox.json` — native sing-box JSON generated from the selected canonical configs.
- `clients/mihomo.yaml` — native Mihomo YAML generated from the selected canonical configs.
- `clients/manifest.json` — credential-free mapping of client/core/format/count.

### Quality profiles

- `profiles/recommended.txt` — high global score, with fallback only to verified universal nodes when the pool is small.
- `profiles/secure.txt` — minimum global + Security score.
- `profiles/max-compat.txt` — the broad verified LIVE pool, score-ranked.

### Network feeds

- `networks/direct-ip.txt`
- `networks/ipv4.txt`
- `networks/ipv6.txt`
- `networks/tcp.txt`
- `networks/udp.txt`
- `networks/port443.txt`
- `networks/mobile-safe.txt`

All text feeds have exact Base64 companions.

### Operator feeds

For every operator dimension present in Stage-9 scorecards, Stage 10 creates `operators/<operator>/manifest.json`. Credential-bearing operator feeds are emitted only when current evidence passes all of:

- operator score threshold;
- confidence threshold;
- `fresh == true` when the policy requires fresh evidence;
- mapped client core PASS;
- client score threshold.

Example paths once physical evidence exists:

```text
operators/mci/v2rayng.txt
operators/mci/hiddify.txt
operators/mci/nekobox.txt
operators/mci/singbox.json
operators/mci/mihomo.yaml
operators/mci/universal.txt
```

If Irancell has no fresh evidence, only `operators/irancell/manifest.json` is produced; no fake Irancell subscription is emitted.

## Important publishing rule

General client/network/profile feeds retain the existing previous-good protection in the guarded publisher. Operator feeds intentionally do **not** inherit an old credential feed when fresh evidence disappears, because preserving it would misrepresent stale operator data as current.

## Diversity and deterministic ranking

Feeds are ranked deterministically by context score, Global score, Reliability, Latency, then safe ID. Diversity limits cap repeated ASN/prefix/source concentration. Small feeds can relax the diversity cap only to satisfy `min_fallback_nodes`; unsupported or unverified nodes are never pulled in as fallback.

## Native hostname semantics

Native Mihomo/sing-box artifacts use the canonical hostname unless the original canonical config is itself direct-IP. The Stage-5 runner-resolved IP is not silently pinned into exported configs.

## Verification

`verify-feed` checks:

- exact Base64/text equality recursively;
- main legacy subscription == `clients/universal.txt`;
- Universal membership matches `universal_compatible` evidence;
- client URI feed membership matches the mapped core PASS status;
- operator feed nodes have fresh operator score evidence;
- native sing-box/Mihomo outputs parse;
- feed manifests are credential-free.

## QA

Stage 10 final regression: 691 Python tests pass in deterministic chunks, plus Python compile, YAML/workflow parse, public-tree verification, Go `test -race`, `go vet`, and Go build.
