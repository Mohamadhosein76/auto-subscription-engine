# Self-Hosted Operator Probes

Operator probes are the only mechanism ASE uses to create operator-specific connectivity evidence. GitHub-hosted runners are useful for general verification but are not representative of MCI, Irancell, Rightel or a particular fixed ISP.

![Operator probe topology](../.github/assets/ase-operator-probe-topology.svg)

## Security model

- Every job/result envelope is versioned and HMAC-SHA256 signed.
- Jobs expire; stale/invalid signatures are rejected.
- The shared secret is read from `ASE_OPERATOR_PROBE_SECRET` and must never be placed in the repository, command arguments, result JSON, persistent state or public artifacts.
- Result IDs are replay-protected.
- `data/operator_probes.json` persists only bounded credential-free evidence.
- The Go supervisor does not implement proxy protocols. It calls the central Python worker so parser/runtime behavior has one implementation.
- All operator profiles share one state file and therefore use one `operator-probe-state` GitHub Actions concurrency group.

## Built-in profiles

`config/operator_probes.yaml` currently defines:

| Profile | Runner label | Intended network |
|---|---|---|
| `mci` | `ase-mci` | physical MCI mobile connection |
| `irancell` | `ase-irancell` | physical Irancell mobile connection |
| `rightel` | `ase-rightel` | physical Rightel mobile connection |
| `fixed` | `ase-fixed` | a specifically provisioned fixed ISP link |

The profile definition is **not evidence that a working runner exists**.

## Provision a runner

1. Provision a Linux machine physically connected to the target network. Avoid routing the probe through a VPN/proxy that changes the network being measured.
2. Register it as a GitHub self-hosted runner for the repository.
3. Add the exact profile label, e.g. `ase-mci`.
4. Create the matching GitHub Environment, e.g. `operator-mci`.
5. Add an Environment secret named `ASE_OPERATOR_PROBE_SECRET` with a high-entropy value. Use a separate secret per Environment/profile if desired.
6. Ensure Python 3.12+, Go and normal build tools are available. The workflow installs the Python package and checksum-verifies pinned proxy cores itself.

## Run through GitHub Actions

Use the manual workflow `.github/workflows/operator-probe.yml` and supply:

- `operator_profile`: `mci`, `irancell`, `rightel`, `fixed` or a configured custom profile.
- `runner_label`: the exact label configured for that profile.

The workflow:

1. checks out full history;
2. installs ASE;
3. installs checksum-pinned cores;
4. builds the Go supervisor into `$RUNNER_TEMP`;
5. assembles published candidates;
6. creates a signed expiring job;
7. runs the probe on that physical network;
8. verifies and ingests the signed credential-free result;
9. commits state only when changed, with bounded non-force push retries;
10. deletes signed jobs/results/candidate files/runtime binaries in an `always()` cleanup step.

## Local/manual job round trip

Use environment variables rather than CLI arguments for the secret:

```bash
export ASE_OPERATOR_PROBE_SECRET='use-a-real-high-entropy-secret'

# Build signed job
auto-subscription-engine operator-probe-job \
  --input candidates.txt \
  --operator-profile mci \
  --runner-label ase-mci \
  --output /tmp/operator-job.json

# Build the Go supervisor
cd src/auto_subscription_engine/core/operator_probe/agent
go build -trimpath -o /tmp/ase-operator-probe ./cmd/ase-operator-probe
cd -

# Run on the physical target network
/tmp/ase-operator-probe run \
  --job /tmp/operator-job.json \
  --output /tmp/operator-result.json \
  --core-dir .core-bin \
  --testing-config config/testing.yaml \
  --operator-profile mci \
  --probe-id local-mci-probe

# Verify signature and persist safe evidence
auto-subscription-engine operator-probe-ingest \
  --input /tmp/operator-result.json \
  --operator-profile mci \
  --state data/operator_probes.json
```

Delete temporary job/result files when finished.

## Freshness and feed boundary

Operator state records have explicit freshness. Stage-9 scoring keeps the operator dimension unknown when evidence is missing; Stage-10 publishes operator credential feeds only from current evidence that meets the configured operator score/confidence/freshness requirements.

A historical success does not justify a permanent claim. When fresh evidence disappears, stale operator credential feeds are intentionally not preserved.
