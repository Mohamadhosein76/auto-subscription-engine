# Stage 6 — Smart Scheduler / Candidate Intelligence

Stage 6 replaces the old deterministic `max_candidates -> max_proxy_candidates`
sampling path with one persistent adaptive scheduler. The hard numbers are now
**safety ceilings**, not "take the same first N nodes every run" rules.

## Central source tree

All Stage 6 domain logic lives under:

```text
src/auto_subscription_engine/core/scheduling/
├── __init__.py
├── engine.py      # adaptive planner + fair selector
├── history.py     # node reliability + persistent scheduling state
├── models.py      # policy, lanes, decisions, plan diagnostics
└── policy.py      # config mapping + validation
```

The replaced package-root `history.py` was deleted. Candidate sampling functions
were also removed from `scoring.py`; scoring once again owns only scoring/ranking.

## Why the old model was weak

The previous live pipeline used two deterministic cuts:

1. protocol-balanced structural sampling (`max_candidates`, typically 1500), then
2. protocol-balanced runtime sampling (`max_proxy_candidates`, typically 400).

This bounded CI cost, but it had no persistent memory of *who did not receive a
slot*. A large, mostly stable pool could therefore repeatedly favor the same
fingerprints while thousands of valid candidates never reached real runtime
verification.

## Persistent candidate intelligence

`data/history.json` schema v4 keeps reliability and scheduling metadata together,
all keyed by irreversible fingerprints and containing no URI, UUID, password or
token.

New scheduling fields:

- `first_discovered`
- `last_discovered`
- `preflight_scheduled_total`
- `runtime_scheduled_total`
- `last_preflight_scheduled`
- `last_runtime_scheduled`

Discovery timestamps are bookkeeping. Scheduling counters/timestamps are
meaningful operational state and must persist between GitHub runs; otherwise
no-starvation rotation would reset every hour.

## Candidate lanes

Each candidate is classified on every plan:

- **exploration** — never verified / still needs real evidence,
- **recovery** — failed previously and is waiting for exponential backoff,
- **flaky** — mixed/low rolling success,
- **healthy** — stable and recently successful,
- **stale** — once known but old enough to require refresh.

The classification is outcome-driven. Country is never used.

## Due-time policy

The scheduler does not waste runtime budget on every healthy node every hour.
Current defaults:

- healthy retest: 180 minutes,
- flaky retest: 45 minutes,
- exploration retry: 60 minutes,
- recovery base backoff: 30 minutes,
- recovery max backoff: 12 hours,
- stale threshold: 24 hours.

Recovery uses exponential backoff based on consecutive failures. When the due
pool is smaller than the safety ceiling, `allow_early_fill` may use spare capacity
on the nearest not-due nodes.

## Budget allocation

`config/testing.yaml -> scheduler` now owns the safety ceilings and allocation
policy:

- `preflight_budget`
- `runtime_budget`
- `exploration_share`
- `recovery_share`
- `direct_ip_share`
- source-quality weighting / soft caps
- retest TTLs / backoff

The default reserved shares protect three important workloads:

1. new/never-tested exploration,
2. failed-node recovery,
3. Stage 4 direct-IP variants.

The rest is filled by globally ranked due candidates.

## Source intelligence integration

Stage 3 source quality is consumed by Stage 6. Better historical sources receive
higher priority and a larger **soft** per-source allowance. Low-quality sources
remain eligible so the system does not create a feedback loop that permanently
hides recovery.

The cap is deliberately soft: if a run has only one source or alternatives are
exhausted, the scheduler relaxes the cap rather than leaving CI capacity unused.

## Protocol fairness

Within every scheduler slice, candidates are consumed round-robin across
protocols. One huge VLESS source therefore cannot crowd Trojan/SS/Hysteria/TUIC
candidates out of the whole run.

## Direct-IP reserve

Candidates whose endpoint is already an IP literal receive an explicit reserve
and priority bonus. This does not declare them healthier; it only guarantees that
Stage 4 static-IP discoveries receive enough verification opportunities to prove
or disprove their value.

## Two independent schedules

Preflight and runtime scheduling state are separate.

A candidate may repeatedly pass cheap endpoint preflight but miss the expensive
runtime budget. Because `runtime_scheduled_total` is tracked independently, such
a candidate is promoted in a later run instead of being hidden forever behind
low-latency incumbents.

## Pipeline position

```text
Discovery / Canonical pool
        ↓
Scheduler seed plan
        ↓
Static-IP Hunter (bounded)
        ↓
Final preflight scheduler plan
        ↓
Endpoint Preflight
        ↓
Runtime scheduler plan
        ↓
Verification Engine v2
        ↓
History outcome update
```

The seed plan bounds DNS work. After Stage 4 creates IP variants, the final
preflight plan is recomputed so direct-IP variants can compete inside the same
hard ceiling rather than increasing total work without bound.

## Diagnostics

`live_stats.json` now includes credential-free scheduler summaries for:

- seed plan,
- final preflight plan,
- runtime plan,
- considered / selected counts,
- due vs early-fill counts,
- selected lanes,
- selected protocols,
- selected sources,
- direct-IP selections.

No proxy URI or authentication material is written to scheduler diagnostics.

## Tests completed

Stage 6 adds deterministic offline tests for:

- never-tested rotation,
- large-pool coverage before recent candidates repeat,
- exponential recovery backoff,
- healthy TTL behavior,
- direct-IP reservation,
- protocol round-robin,
- adaptive source quality budget,
- runtime promotion of preflight survivors,
- scheduler policy validation,
- scheduling-state persistence,
- central-source-tree guards,
- meaningful-history persistence semantics.

The live pipeline integration tests additionally verify that scheduler summaries
are emitted and the legacy public feed contract remains valid.

## Final verification

The completed Stage 6 worktree passed:

- `652 passed`, `0 failed`,
- Python `compileall`,
- YAML validation for project config + workflows,
- `verify-publish` against the current public tree,
- `git diff --check`,
- Stage 5 -> Stage 6 structural fixture regression: `subscription.txt` and
  `subscription_base64.txt` are byte-identical; only volatile `generated_at` in
  `stats.json` differs.
