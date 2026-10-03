# Stage 9 — Multidimensional Scoring Engine v2

## Goal

Turn the evidence created by Stages 5–8 into one credential-free scorecard per
node without changing feed membership yet. Stage 10 is the only stage allowed
to consume these scores for new feed policy.

## Central source tree

All score math now lives in:

```text
src/auto_subscription_engine/core/scoring/
├── compatibility.py
├── engine.py
├── models.py
├── policy.py
├── preselection.py
└── stage.py
```

Removed replaced implementations:

- `src/auto_subscription_engine/scoring.py`
- `src/auto_subscription_engine/core/clients/compatibility/score.py`

## ScoreCard schema

Each `live_nodes.json` entry receives a `scores` object and its top-level
`score` becomes `scores.global.score`.

The scorecard contains:

- global quality + confidence;
- connectivity and latency evidence;
- reliability from persistent node history;
- freshness with explicit time decay;
- security quality derived from security risk/completeness;
- one independent score per configured operator probe;
- one independent score per verified client/core mapping.

Unknown operator/core evidence is `score: null`; it is never treated as a
failure. Explicit runtime `fail`/`unsupported` evidence is scored as zero.

## Global formula

Default final global weights:

- connectivity 30
- latency 20
- reliability 25
- freshness 10
- security 15

Operator and client scores are not inputs to global quality. This prevents a
node from looking globally bad simply because one operator has no probe yet.

## Operator score

When signed Stage-8 evidence exists, each operator gets an independent score:

- current connectivity 45
- rolling operator reliability 30
- operator-observed latency 15
- evidence freshness 10

The score also carries `fresh`, confidence, evidence count, operator display
name/network type and the runtime core that proved the result. No credentials
are persisted.

## Client score

Every published client maps to its actual tested core using the Stage-7
registry. A current core pass receives runtime credit plus per-core historical
reliability and the current compatibility latency. Explicit fail/unsupported is
zero. Unavailable/untested remains unknown (`null`).

## Pipeline position

```text
Verification -> Security -> Multi-Client Compatibility
             -> Stage 9 Scoring -> verify-score -> Publish
```

Stage 9 intentionally does not reorder or create feeds. Existing subscription
content remains unchanged; only credential-free metadata is enriched.

## New artifacts

- `output/scorecards.json`
- `live_nodes.json[*].scores`
- `live_stats.json.scoring_v2`

The main workflow uploads `scorecards.json` as a diagnostic artifact.

## Safety / validation

`verify-score` checks:

- every node has all required score dimensions;
- all numeric scores/confidence are in 0..100;
- top-level `score` equals final global score;
- `scorecards.json` exactly matches `live_nodes.json` scorecards;
- no URI/UUID/password/token/secret-shaped data exists in score payloads;
- stats counters match scorecard count.

## Migration / compatibility

The pre-security selection formula is preserved under
`core/scoring/preselection.py`, so Stage 9 does not change the candidate/feed
contract before Stage 10. Compatibility ranking math moved unchanged into the
same central scoring subsystem.

## QA / regression result

Stage 9 was validated with:

- 685 Python tests passing;
- `python -m compileall -q src`;
- YAML parse for testing/operator/workflow files;
- `verify-publish` against the committed public tree;
- `go test -race ./...`, `go vet ./...`, and a clean Go agent build;
- `git diff --check`;
- an end-to-end score pass over the current 83 published metadata entries;
- byte-identical `subscription.txt` and `subscription_base64.txt` before/after Stage-9 scoring.

The current repository has no signed MCI/Irancell/Rightel/Fixed evidence yet, so
operator scores correctly remain unknown (`null`) instead of being fabricated.
