# Stage 11 — Production Hardening

Status: COMPLETE (implementation phase; final release remains Stage 12)

## Goal

Stage 11 does not add a new proxy protocol or feed. It removes failure modes that could corrupt persistent intelligence, leave the published tree missing after a crash, leak temporary operator credentials, leave orphan core processes, or allow an incomplete run to be committed.

## Central hardening tree

```text
src/auto_subscription_engine/core/hardening/
├── __init__.py
├── state.py        # durable state IO + backup recovery
├── publication.py  # guarded publish + interrupted-swap recovery
└── release.py      # read-only production release gate / health report
```

The replaced package-root `publisher.py` is deleted. Publication now has one implementation under `core/hardening/`.

## Durable persistent state

The following state stores now share Stage-11 durable IO:

- `data/history.json`
- `data/discovery.json`
- `data/ip_history.json`
- `data/operator_probes.json`

Write contract:

1. Serialize deterministic JSON.
2. Snapshot the current primary as `<file>.bak` when present.
3. Write a same-filesystem temporary file.
4. Flush + `fsync` the file.
5. `os.replace()` the primary atomically.
6. `fsync` the containing directory on a best-effort basis.

Read contract:

- Missing state is allowed and starts empty.
- Corrupt primary + valid backup -> restore the last-known-good backup.
- Corrupt primary + corrupt/missing backup -> fail closed with `StateCorruptionError`.
- Existing corruption is never silently interpreted as an empty state database.

Backup files are ignored by Git and exist only as runtime recovery artifacts.

## Crash-recoverable publication

`run_publish()` now starts with interrupted-transaction recovery.

Covered crash windows:

- stale `public.staging/` from an interrupted pre-promotion run -> discard and rebuild;
- `public/` renamed to `.public.old-*` but staging not promoted -> restore previous healthy public tree;
- new `public/` promoted but old backup not cleaned -> keep new public and remove stale backup.

Before touching the old public tree, the publisher also verifies staging and public parents are on the same filesystem. Promotion renames are followed by best-effort directory `fsync` barriers.

## Production release gate

New CLI:

```bash
auto-subscription-engine production-check \
  --repo-root . \
  --output-dir output \
  --public-dir public \
  --report output/production_health.json
```

The gate is read-only and runs after `verify-publish` but before auto-commit/push.

It validates:

- promoted public tree;
- Stage-9 scorecards;
- Stage-10 feed outputs;
- config + workflow YAML parseability;
- persistent JSON state readability and size bounds;
- no proxy URI / UUID / sensitive key leakage in operational state;
- no stale publish staging/backups/temp files;
- no tracked `__pycache__`, `.pytest_cache`, `.egg-info`, `.core-bin`, or `.bak` artifacts.

Any failure blocks commit/push. The previous remote `public/` therefore remains the last healthy release.

## Runtime process hygiene

Every proxy core is spawned in its own POSIX process group. Cleanup first sends group `SIGTERM`, waits briefly, then escalates to group `SIGKILL` when necessary. This prevents helper/child processes from surviving an exception or cancellation.

## Operator workflow hardening

All operator profiles write one shared `data/operator_probes.json`, so the workflow now uses a single concurrency group (`operator-probe-state`) instead of per-operator groups. This prevents MCI/Irancell/etc. from racing on the same file.

The operator job now also has:

- explicit 45-minute timeout;
- bounded 3-attempt fast-forward push/rebase loop;
- no force push;
- `always()` cleanup of signed job/result files, candidate list, Go agent binary and downloaded cores.

## Failure semantics

Stage 11 intentionally prefers "fail and preserve previous healthy release" over "reset and continue" for state corruption. Security feed cache corruption remains refreshable by design; if required security intelligence cannot be recovered/fetched, the existing security-unavailable guard prevents publication.

## Stage boundary

Stage 11 does not rewrite the README visuals/final release packaging, remove every remaining pre-central root orchestration file, or perform the final GitHub-ready repository presentation. Those are Stage 12 responsibilities.
