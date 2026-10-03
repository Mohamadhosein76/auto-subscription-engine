# Stage 3 — Discovery Engine / Source Intelligence

## Status

Implemented on branch `ase-next/stage-3-discovery`.

## Goal

Replace the fixed, serial seven-source collector with one central, bounded discovery subsystem
that can learn source quality, follow nested subscription/provider links, quarantine unhealthy
sources, and feed verified outcomes back into future source ordering.

Stage 3 does **not** implement static-IP hunting or operator probes. Those remain Stage 4 and
Stage 8 respectively.

## Central source tree

All Stage 3 source/discovery logic lives under:

```text
src/auto_subscription_engine/core/discovery/
├── __init__.py
├── catalog.py         seed source config loader
├── config.py          bounded discovery policy
├── engine.py          recursive deterministic crawler
├── fetch.py           bounded HTTP source fetcher
├── intelligence.py    persistent source quality/quarantine store
├── models.py          discovery/source data models
├── ordering.py        learned source ordering
└── url.py             source URL validation/canonical IDs
```

The replaced root modules `sources.py` and `fetcher.py` were deleted. Their business logic is
not duplicated elsewhere. The Stage 2 compatibility shims (`models.py`, `decoder.py`,
`normalize.py`, `validation.py`, `b64util.py`, and the root `parsers/` package) were also removed
after all production/test imports were migrated to the central `core/` tree.

## Recursive discovery

The discovery engine starts from `config/sources.yaml` and can follow nested sources exposed by
Stage 2 ingestion, including plain subscription URLs, Hiddify import links resolved to HTTP(S),
and Clash/Mihomo `proxy-providers` URLs.

Hard bounds are configured in `config/discovery.yaml`:

- maximum graph depth
- maximum total sources per run
- maximum nested sources per parent
- maximum proxy candidates
- bounded fetch concurrency

Duplicate source URLs are canonicalized and fetched once per run.

## Concurrent but deterministic

HTTP source fetches run with bounded concurrency. Completion order never determines output order:
results are processed in scheduler order after each batch so stats and candidate selection stay
reproducible.

## Source intelligence

Persistent source intelligence moved out of node `history.json` into:

`data/discovery.json`

The store intentionally persists **no source URL**, query string, credential, proxy URI, UUID, or
password. It stores only source IDs, human labels/hosts, counters, timestamps, quarantine state,
and verification outcomes.

Quality combines:

- fetch success rate
- duplicate/yield quality
- parser health
- actual TCP/proxy/client verification outcomes
- bounded productivity

Runtime TCP/proxy outcomes from the live pipeline and compatibility outcomes from the multi-core
stage feed back into this single source-intelligence model.

## Quarantine

Repeated fetch failures trigger exponential temporary quarantine. A later successful fetch clears
quarantine automatically. This prevents a persistently dead source from consuming the same budget
every hour without permanently deleting it.

## Historical migration

The seven legacy source counters previously stored inside `data/history.json` were migrated into
`data/discovery.json`. `history.json` is now node reliability only; there is no second source-quality
implementation left there.

## Pipeline integration

The structural pipeline now uses Stage 2 multi-format ingestion for both local and remote content.
Remote collection goes through the Stage 3 discovery graph rather than the deleted legacy fetcher.
This means structured Clash/Mihomo, sing-box, Xray, Base64, and URI sources can participate in the
same source discovery path.

## CI persistence

The hourly GitHub workflow now passes `config/discovery.yaml` and `data/discovery.json` through the
structural, live and compatibility stages and commits bounded source intelligence together with
published output/history/security data.

## Architecture rule locked by owner

When a subsystem is migrated into the central `core/` tree, the replaced implementation must be
deleted in the same stage. Compatibility shims may exist only for subsystems not yet migrated and
must not receive new business logic. Final delivery must contain one authoritative implementation
per concern.

## Verification snapshot

At Stage 3 completion:

- full pytest suite: **629 passed / 0 failed**
- Python compileall: **PASS**
- `verify-publish --public-dir public`: **PASS**
- `git diff --check`: **PASS**
- Stage 2 mixed fixture vs Stage 3: **BYTE IDENTICAL** for both plain and Base64 subscriptions
- replaced root source/fetch modules: **deleted and guarded by tests**
