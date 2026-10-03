# ASE 1.0 — Final Release Notes

ASE 1.0 is the Stage-12 final release built on the completed Stage-11 production-hardening baseline.

## Final source-tree consolidation

Stage 12 removed the final package-root business-logic implementations and moved their canonical implementations into the single authoritative `core/` tree:

- deduplication -> `core/models/dedup.py`
- country/geolocation -> `core/network/geo.py`
- live/pipeline/output verification orchestration -> `core/orchestration/`
- safe identity/redaction -> `core/utils/`
- Security Intelligence -> `core/security/`

No permanent import shim remains at the deleted paths. The package root now contains only `__init__.py`, `__main__.py`, `cli.py` and the central `core/` package. Regression guards prevent those old paths from returning.

The obsolete development `worklog.md` was removed. Historical stage records were preserved, but moved under `docs/stages/` so they are clearly separated from current documentation.

## Configuration cleanup

Stage 12 audited tracked YAML against production consumers. Two existing settings that were present in configuration but bypassed by hard-coded behavior were wired into the real implementation:

- `compatibility.min_universal_nodes` now feeds the actual guarded `PublishOptions` value.
- `compatibility.mobile_safe.udp_share_cap` now feeds the actual mobile-safe selector instead of a hard-coded 0.20 helper.

Stale migration comments were removed from final-facing config/workflow files. `docs/CONFIGURATION.md` documents the active settings.

## Version and HTTP identity

The Python project version is `1.0.0`. Shared outbound project identification now comes from `core/version.py` instead of multiple hard-coded `0.1.0` User-Agent strings.

## Final QA fixes

Stage-12 release QA exposed an intermittent localhost-port reuse race in rapid core launches. `allocate_port()` still asks the kernel for an ephemeral port, but now rejects recently issued process-local port numbers with bounded history before launching a core. This removes immediate duplicate allocations while preserving the runtime startup health check as the final authority for external bind races. A 200-allocation stress check and the compatibility/runtime regression tests pass with the fix.

## Documentation and visuals

The final release adds a redesigned root README plus dedicated current documentation for:

- architecture and subsystem boundaries;
- Discovery and Static-IP Hunter;
- verification, scheduling and multi-client runtime;
- self-hosted operator probes;
- multidimensional scoring and feed publication;
- production security/hardening;
- installation, configuration, feeds/URLs and development QA.

GitHub visuals live only in `.github/assets/` and include a repository hero plus distinct architecture, discovery, verification, operator-probe and publish diagrams. The visual/text documentation explicitly preserves the project's evidence boundaries: it does not claim current MCI/Irancell/Rightel/fixed connectivity or unsupported GUI compatibility without real evidence.

## Backward compatibility

The legacy public subscription contract remains intact. In particular, Stage 12 does not break the stable main subscription paths:

```text
public/subscription.txt
public/subscription_base64.txt
```

The existing client paths also remain part of the documented public contract. Modern successful publication keeps the main subscription aligned with the universal feed.

## Release QA

The final release is accepted only after the full Python suite, Go race tests, Go vet/build, compileall, YAML/workflow parsing, public/score/feed/production verifiers, credential-leak scan, legacy-path guards, `git diff --check` and a completely clean checkout QA all pass. Exact final results, artifact SHA-256 values, final commit and final tag are recorded in the separately generated Final Release Report delivered with the release artifacts.
