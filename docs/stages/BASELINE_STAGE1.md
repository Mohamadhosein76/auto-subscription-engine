# ASE Next - Stage 1 Baseline

Baseline captured on 2026-10-02 before any discovery, scheduling, protocol, or
operator-aware redesign. This document is deliberately factual: it records the
current system so later stages can prove improvements without losing working
behaviour.

## Git safety point

- Baseline commit: `0198cc6` (`chore: refresh live subscription`)
- Local rollback tag: `ase-baseline-20261002`
- Stage branch: `ase-next/stage-1-baseline`
- No Stage 2+ feature work is included here.

## Current published state

From the committed `public/live_stats.json` and `public/status.json`:

- Last successful publish: `2026-10-01T07:15:45+00:00`
- Configs received: 15,449
- Valid configs before dedup: 15,051
- Unique final configs: 11,290
- TCP candidates/tested: 1,500 / 1,500
- TCP passed: 685
- Real proxy candidates/tested: 400 / 400
- Proxy-live before security: 83
- Security-publishable: 61
- Universal feed: 6
- v2rayNG feed: 10
- Hiddify feed: 16
- NekoBox feed: 20
- Mihomo feed: 14
- Configured sources: 7

These numbers are a baseline only, not a target.

## Baseline test state

Before Stage 1 hardening:

- `python -m pytest` failed during collection because the src-layout package was
  not discoverable unless the project had first been installed or
  `PYTHONPATH=src` was manually supplied.
- With `PYTHONPATH=src`, 588 tests passed and one time-sensitive security-cache
  test failed because its hard-coded clock date aged out.

Stage 1 fixes both reproducibility problems without changing proxy-selection
logic.

## Public URL compatibility contract

The following existing paths are now regression-tested and must not disappear
silently in later refactors:

- `public/subscription.txt`
- `public/subscription_base64.txt`
- `public/best.txt`
- `public/clients/universal.txt`
- `public/clients/v2rayng.txt`
- `public/clients/hiddify.txt`
- `public/clients/nekobox.txt`
- `public/clients/mihomo.yaml`
- `public/networks/mobile-safe.txt`
- `public/status.json`

Base64/plain pairs are also checked for byte-equivalent content.

## Stage 1 validation added

- Dedicated read-only `.github/workflows/ci.yml` runs on pushes and pull requests.
- CI compiles the package, runs the full offline suite, and validates the committed `public/` tree.
- The scheduled publishing workflow remains separate and retains its existing guarded/transactional behavior.

## Stage 1 acceptance criteria

1. A clean checkout can run `python -m pytest` without manually setting
   `PYTHONPATH`.
2. The complete offline test suite passes.
3. Existing public feed paths remain protected by regression tests.
4. Workflow safety invariants remain intact: hourly/manual trigger,
   concurrency guard, bounded timeout, no force push, standard GitHub token,
   guarded publish, and atomic public promotion.
5. The original baseline remains reachable by tag.
6. No discovery, operator routing, scoring, parser expansion, or static-IP
   hunting logic changes in this stage.

## Stage 1 verification result

- `python -m compileall -q src`: PASS
- `python -m pytest -q`: **597 passed**
- `python -m auto_subscription_engine verify-publish --public-dir public`: PASS
- `git diff --check`: PASS
