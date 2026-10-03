# Security & Production Hardening

ASE treats verification, security policy and publication safety as separate concerns. A node can be syntactically valid yet fail runtime verification; a LIVE node can still be rejected by security policy; a healthy candidate set can still be blocked from publication if release invariants fail.

## Security Intelligence Layer

Security runs on the verified LIVE pool and combines:

- official/key-free reputation feeds (Spamhaus DROP/DROPv6/ASN-DROP and Feodo recommended C2 data);
- ASN lookup via Team Cymru with configured fallback;
- independent DNS diagnostics;
- normal TLS certificate + hostname verification through the tunnel;
- bounded HTTPS content-integrity probes through the tunnel;
- policy constraints such as forbidden ASN rules and concentration limits.

There is no `verify=False`, `CERT_NONE` or hostname-verification bypass in the production TLS path.

## Security decisions

The policy layer can produce:

- `ALLOW`
- `ALLOW_WITH_WARNINGS`
- `QUARANTINE`
- `BLOCK`

Incomplete security evidence is represented explicitly. Depending on policy it may produce a warning or quarantine; it is not silently converted to a clean pass.

## Credential boundaries

Proxy subscription files necessarily contain credentials embedded in share URIs. Those URI files are the intended secret-bearing *content* of a public proxy subscription.

The following operational stores must stay credential-free:

- `data/history.json`
- `data/discovery.json`
- `data/ip_history.json`
- `data/operator_probes.json`
- scorecards and feed manifests
- `production_health.json`
- operator job/result persistent state after ingestion

The production release gate scans operational state for proxy URI/UUID/sensitive-key leakage and rejects a release when the boundary is violated.

## Durable state

Stage 11 introduced one durable JSON I/O implementation in `core/hardening/state.py`:

1. serialize deterministic JSON;
2. preserve the current primary as `<file>.bak` when applicable;
3. write a temporary file on the same filesystem;
4. flush + `fsync` the file;
5. atomically `os.replace()` the primary;
6. best-effort `fsync` the directory.

Read behavior:

- missing optional state can start empty;
- corrupt primary + valid backup restores the last-known-good backup;
- corrupt primary + corrupt/missing backup raises `StateCorruptionError` and fails closed.

State corruption is never silently treated as a brand-new empty database.

## Transactional publication

`core/hardening/publication.py` stages a candidate public tree, verifies it, then promotes it with same-filesystem renames. Interrupted transaction recovery handles:

- stale `public.staging/` before promotion;
- old public renamed but new staging not promoted;
- new public promoted but old backup not yet removed.

The publisher checks that staging/public parents live on the same filesystem before relying on atomic rename behavior.

## Production release gate

```bash
auto-subscription-engine production-check \
  --repo-root . \
  --output-dir output \
  --public-dir public \
  --report output/production_health.json
```

The read-only gate checks, among other things:

- the promoted public contract;
- Stage-9 scorecards and Stage-10 feed output;
- YAML/config/workflow parseability;
- state readability and size limits;
- sensitive data in credential-free operational state;
- stale staging/temp/backup artifacts;
- tracked caches, egg-info, core binaries and backups.

A failure blocks auto-commit/push. The previous healthy remote public tree remains the last known good release.

## Process and workflow hygiene

Proxy cores run in their own POSIX process groups. Cleanup sends group `SIGTERM`, waits, then escalates to group `SIGKILL` if necessary so helper children do not survive cancellation/exceptions.

Operator workflows serialize writes to shared state, have explicit timeouts, never force-push and unconditionally remove temporary credentials/artifacts.

## Supply chain

Proxy cores are pinned to explicit versions and archive SHA-256 values in `config/testing.yaml`. Archives are checksum-verified before extraction; downloaded binaries are runtime-only and are not tracked in Git.
