# Cross-Platform Audit (Phase 1 of the Windows/Android upgrade)

Audit of the Final Stage 12 baseline (commit content `74833dc9…`, tag
`ase-v1.0.0-20261003`) for Linux-specific assumptions, and the disposition
of every finding.

## Findings and disposition

| # | Finding | Location | Disposition |
|---|---|---|---|
| 1 | Cores pinned to Linux artifacts only | `config/testing.yaml` | Fixed: per-platform manifests (`linux-amd64` + `windows-amd64`) for all four cores, official URLs, SHA-256 per artifact |
| 2 | Installer assumed extension-less binaries | `core/clients/install.py` | Fixed: platform-aware binary names via `core.platform.executable` (`xray.exe`, `HiddifyCli.exe`, …) + per-platform spec selection |
| 3 | `chmod 0o755` on extracted binaries | `core/clients/install.py` | Fixed: POSIX-only `ensure_executable` |
| 4 | Single-member extraction only | `core/clients/install.py` | Extended: multi-member extraction (hiddify Windows ships `HiddifyCli.exe` + DLLs), `tar.xz` added |
| 5 | `start_new_session` POSIX-guarded but Windows only `terminate()`/`kill()` (children orphaned) | `core/clients/runtime.py` | Fixed: `core.platform.process` — `CREATE_NEW_PROCESS_GROUP\|CREATE_NO_WINDOW`, tree teardown via `taskkill /T` (force fallback); POSIX group semantics unchanged |
| 6 | `workdir.chmod(0o700)` unguarded | `core/clients/runtime.py` | Fixed: POSIX-only |
| 7 | `os.chmod(0o600)` on config writers | `builders/adapters.py`, `builders/singbox.py` | Fixed: centralized `set_owner_only_permissions` (no-op on Windows) |
| 8 | `write_text` used platform-native newlines → CRLF corruption of base64 feed pairs on Windows | 15 writer modules (50 call sites) | Fixed: all artifact/state writers pin `newline="\n"`; public contract tests assert CR-free bytes |
| 9 | Fake-core test fixtures relied on shebang exec | `tests/stage5`, `tests/test_compat_runner.py` | Fixed: platform-correct launchers (`.cmd` shim on Windows) |
| 10 | Permission assertions asserted POSIX modes | several tests | Fixed: platform-conditional assertions matching each platform's real semantics |
| 11 | `/tmp`, `/usr/bin`, `shell=True`, `bash`, `which` | — | Audit: none existed (tempfile-based paths already) |
| 12 | Windows dead-port behavior (timeout instead of refused) | security probe tests | Fixed: honest-outcome assertions (`inconclusive` accepted alongside `transport_error`) |

## Already portable at baseline

- No `/tmp` or `/usr/bin` hardcodes; temp paths via `tempfile`.
- No `shell=True`, no `bash`, no `shutil.which` in production code.
- Safe extraction (checksum before extract, size caps, pinned members).
- `start_new_session` already guarded by `os.name == "posix"`.
- Port allocation race fix (Stage 12) preserved; new Windows-specific
  allocation tests added.

## Verification

- Full test suite on native Windows: **763 passed / 0 failed**
  (baseline had 23 Windows-only failures — all fixed for real, none disabled).
- Real Windows QA: all four official cores downloaded, checksum-verified,
  executed (`version` commands); end-to-end runtime fixture verified
  `PROXY_TUNNEL_OK` through sing-box with clean teardown.
- `windows-ci.yml` runs the same suite + core smoke on `windows-latest`.
