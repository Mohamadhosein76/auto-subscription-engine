# ASE Final Release Report — v1.1.1

## Root cause (Hiddify Android real-device issue)

Real-device observation (Android, Hiddify): most of the 53 published
configs showed failed/red; ~4 were usable. The audit of the live feed
eliminated the suspected in-engine causes and isolated the dominant one:

| Suspected cause | Audit result |
|---|---|
| Fallback / weak-evidence nodes in feed | **Ruled out** — all 53 nodes had genuine `hiddify_compatible=pass` (58/58 compat pass) with client score ≥ 50 |
| Serializer mutation (round-trip) | **Ruled out** — 248 published URIs round-tripped canonical → URI → re-parse with **zero** semantic changes (SNI/Host/path/security/Reality/ALPN/flow preserved) |
| Stale evidence | **Partially** — platform feeds mirrored client feeds byte-for-byte, so carried-over metadata from earlier runs could persist |
| **Network path (dominant)** | **Confirmed** — evidence is measured from GitHub datacenters; the device tests from an Iranian ISP. 53/60 nodes were direct-IP on non-standard ports (frequently blocked from Iran); CDN-fronted/port-443 nodes work |

## Feed-policy changes (no verification weakened; feed size is not a KPI)

- Per-node `compat_verified_at` (UTC) stamped by the compatibility stage on
  nodes evaluated in the **current run**; carried-over metadata stays
  unstamped and counts as stale.
- `platforms/<family>/` feeds are no longer byte-mirrors: a client-aware
  gate now applies — client runtime status `pass` AND client score ≥
  `platform_min_client_score` (55, stricter than the client feeds' 50) AND
  evidence fresh (≤ `platform_runtime_evidence_max_age_hours`, 26h) —
  with **no fallback** at platform level.
- Platform manifests (schema v2): `selection_policy`, `generated_at`,
  `runtime_evidence_max_age_hours`, `device_validation:
  manual_observation_only`, `operator_validation: unknown`.
- `verify-feed` now validates platform trees: client status pass, fresh
  current-run evidence, subset of the source client feed, manifest present.
- Real-device observation recorded as `manual_device_observation` in
  docs + manifests — never as automated evidence.

## Files changed (v1.1.1)

- `src/auto_subscription_engine/core/feeds/policy.py` — platform knobs
- `src/auto_subscription_engine/core/feeds/engine.py` — qualification-aware platform feeds
- `src/auto_subscription_engine/core/feeds/verify.py` — platform feed verification
- `src/auto_subscription_engine/core/clients/compatibility/engine.py` — `compat_verified_at`
- `src/auto_subscription_engine/core/clients/registry.py` — alias mapping fix
- `config/feeds.yaml` — platform gate section
- `docs/ANDROID_CLIENTS.md`, `README.md` — evidence boundaries
- `tests/platform_contracts/` — refreshed contracts + fresh/stale fixture
- `tests/stage10/test_feed_engine.py` — fixture freshness
- `pyproject.toml` — 1.1.1

## Real production statistics (gated run 37187312039, published)

- discovery → verification pipeline: green end-to-end
- live nodes: 25 (previous cycle: 31 — hourly pool volatility)
- `clients/hiddify.txt`: 22 qualified
- **`platforms/android/hiddify.txt`: 22** (gate: pass + score ≥ 55 + fresh; was 53)
- windows: hiddify 22, mihomo 25, nekobox 23, singbox 23, v2rayn 16
- One intermediate run (37186163795) measured exactly **4** qualified
  Hiddify nodes on a weak cycle — matching the manual device observation.
  Another cycle was guard-skipped (`skipped_min_universal`, 0 universal
  nodes) and the previous healthy tree was preserved — the transactional
  guard working as designed.

## CI

- **Windows CI** (`windows-latest`): green — full suite, platform
  contracts, core smoke install + real binary execution, CLI smoke.
- **Build Subscription** (Linux production): green — `publish decision:
  published`, auto-commit `ff2fe44`.
- Note: two earlier manual runs failed for environmental reasons (an
  auto-commit race with the hourly cron; a guard-skip on a weak cycle) —
  both are by-design behaviors, documented here.

## Tests

- Full Python suite on native Windows: **765 passed / 0 failed**
  (incl. 55 platform-contract tests; stale-evidence exclusion test added)
- `go build` / `go vet` / `go test -race`: pass
- compileall, YAML validation, workflow validation, `verify-publish`,
  credential-leak scan (0 hits), `git diff --check`: pass

## Live verification (post-publish)

- All platform feeds HTTP 200, non-empty, fully parseable, manifest-
  consistent (file line counts == manifest `nodes`), `status.json` fresh
  (`generated_at` = publish time, `node_count: 25`).

## Known evidence boundaries

- CI runtime verification ≠ Android/Windows GUI device validation.
- A node can pass server-side runtime verification and still fail on a
  specific ISP/device/client combination (dominant cause here: Iranian
  ISP blocking of direct-IP endpoints on non-standard ports).
- Device evidence remains `manual_observation_only`; operator
  compatibility remains `unknown` until physical operator probes run.

## Release identity

- Final commit on `main`: see `git rev-parse HEAD` (printed at packaging)
- Tag: `ase-v1.1.1-cross-platform` (previous tag `ase-v1.1.0-cross-platform`
  left untouched)
- Artifacts: `auto-subscription-engine-v1.1.1-cross-platform-FINAL.zip`,
  `auto-subscription-engine-v1.1.1-cross-platform-FINAL.bundle`,
  `SHA256SUMS.txt`
