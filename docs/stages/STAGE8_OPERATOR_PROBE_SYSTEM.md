# Stage 8 - Iran Operator Probe System

Stage 8 adds a real-network evidence plane without duplicating protocol logic.
The proxy protocol builders and runtime truth remain in the central Python
engine (`core/clients` + `core/verification`). A small Go supervisor runs on a
self-hosted machine physically connected to the target network, authenticates
bounded jobs, invokes the central worker, rejects sensitive result payloads,
and signs the credential-free result for ingestion.

## Central source tree

```text
src/auto_subscription_engine/core/operator_probe/
├── config.py
├── envelope.py
├── jobs.py
├── matrix.py
├── models.py
├── store.py
├── worker.py
└── agent/
    ├── go.mod
    ├── cmd/ase-operator-probe/main.go
    └── internal/
        ├── envelope/
        └── runner/
```

There is no second VLESS/VMess/TUIC implementation in Go. The remote worker
reuses the same Xray/sing-box/Hiddify/Mihomo adapters and Stage-5 verification
policy already used by the main engine.

## Initial operator profiles

`config/operator_probes.yaml` ships with four initial profiles:

- `mci` - mobile
- `irancell` - mobile
- `rightel` - mobile
- `fixed` - fixed-access probe

Profiles are data, not code. Additional fixed ISPs or regional probes can be
added by adding another profile and a self-hosted runner label.

## Trust boundary

The repo never stores the probe HMAC secret. Each GitHub Environment can define
its own `ASE_OPERATOR_PROBE_SECRET`, so MCI, Irancell and Rightel runners do not
need to share a credential.

The wire format is a versioned HMAC-SHA256 envelope:

```text
version + kind + base64(raw JSON payload) -> HMAC-SHA256
```

Two envelope kinds exist:

- `probe_job` - expiring input; may contain public proxy share URIs and is kept
  only in a temporary runner directory with mode 0600.
- `probe_result` - credential-free evidence signed by the Go agent.

Both Python and Go implement the same envelope format. The Go test suite contains
an exact vector produced by the Python implementation.

## Result privacy / integrity

Before a result is signed, the Go agent rejects payloads containing:

- `uri` / `original_uri`
- `password`
- `uuid`
- `token`
- `secret`
- any string containing `://`

The Python ingester enforces the same rule again. Persistent
`data/operator_probes.json` therefore contains fingerprints, safe IDs,
operator evidence, core names, latency and aggregate history only.

The ingester also rejects:

- bad HMAC signatures
- wrong operator profiles
- replayed `result_id` values
- stale results
- results timestamped materially in the future
- unsupported result schemas

## Remote runtime flow

```text
Control plane
   |
   | signed / expiring probe_job
   v
Go agent on self-hosted runner attached to operator
   |
   | verifies HMAC + operator profile
   | decodes job to private temp file
   v
Central Python operator worker
   |
   | canonical parse + fingerprint integrity check
   | Stage 5 endpoint preflight
   | Stage 7 compatible core selection
   | real Xray / sing-box / Hiddify / Mihomo tunnel
   | repeated HTTP/HTTPS quorum
   v
credential-free result JSON
   |
   | Go leak check + job-id check + HMAC signature
   v
signed probe_result
   |
   v
Control-plane ingest -> data/operator_probes.json
```

## Persistent evidence

Per fingerprint and operator, the store retains:

- latest pass/fail status
- runtime core that proved the result
- success ratio
- p50 / p95 latency and jitter
- last observation time
- probe ID
- checks total / checks passed
- rolling success rate

Freshness is evaluated separately. An old PASS is not silently converted to a
current PASS; `matrix.operator_record()` exposes `fresh=false` once the profile
TTL is exceeded. Stage 9 will consume that evidence for scoring and Stage 10
will consume it for operator-specific feeds.

## GitHub self-hosted workflow

`.github/workflows/operator-probe.yml` is intentionally manual until physical
runners exist. It:

1. checks out the repo on a self-hosted runner with the requested network label;
2. verifies/installs checksum-pinned cores;
3. builds the Go agent from source;
4. creates a bounded signed job from current published client/network feeds;
5. runs real tunnel verification from that operator network;
6. verifies and ingests the signed result;
7. commits only credential-free `data/operator_probes.json` when it changed.

The job file is never uploaded as an artifact because it contains share URIs.

## What Stage 8 proves and what it does not

The implementation and cross-language protocol are tested in CI/local tests.
This environment does not have a physical MCI/Irancell/Rightel SIM or fixed ISP
runner, so Stage 8 does **not** claim that any current node has already passed
those networks. That claim becomes valid only after the corresponding physical
self-hosted probe is connected and returns signed evidence.

## QA gates

Stage 8 adds Python tests for:

- profile loading
- signed envelope tamper rejection
- bounded/deduplicated jobs
- direct-IP awareness
- result replay/staleness/operator mismatch
- sensitive field rejection / credential-free state
- freshness matrix semantics
- worker reuse of the central verification engine
- fingerprint tamper rejection
- CLI job generation and result ingestion
- central source-tree guard
- self-hosted workflow/secret guard

The nested Go module has its own `go test ./...`, and root CI now runs it on
every branch/PR.

## Final Stage 8 verification

- Python suite: **673 passed / 0 failed**.
- Nested Go module: `go test -race ./...` **PASS**.
- Go static checks: `go vet ./...` **PASS**.
- Go binary build with `-trimpath`: **PASS**.
- Python `compileall`: **PASS**.
- YAML parsing for testing/operator/CI/workflow files: **PASS**.
- committed `public/` verification: **PASS**.
- `git diff --check`: **PASS**.
- Python-signed job -> Go agent -> Python result-ingest protocol round trip: **PASS**.
- Stage 7 vs Stage 8 structural fixture regression: plain and Base64 subscriptions are
  byte-identical (plain SHA-256 `b64efd2293c33fdf5e4c84d5dfb7d55b7a68f1a699301b0722ee9abb333c1e6f`).

No physical Iranian operator runner exists in this container, so the QA result is
an implementation/protocol guarantee, not a fabricated MCI/Irancell/Rightel
connectivity claim.
