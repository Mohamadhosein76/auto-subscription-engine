# Windows Support

ASE runs natively on Windows 10/11 x64 inside PowerShell (no WSL required).

## Validation record (real, measured on this repository)

| Item | Value |
|---|---|
| OS | Windows 10/11 x64 (verified on a real machine, plus `windows-latest` in CI) |
| Python | 3.12+ required (project constraint); validated with 3.14.0 locally and 3.12 in CI |
| Full test suite | 763 passed / 0 failed (native Windows run) |
| Core installs | all four pinned cores install from official releases, checksum-verified |
| Core binaries executed | xray 26.6.27, sing-box 1.14.2, hiddify-core 4.1.0 (HiddifyCli.exe), mihomo 1.19.31 — each `version` command run on Windows |
| End-to-end runtime fixture | real xray server on 127.0.0.1 → engine spawned sing-box → tunneled real HTTPS → `PROXY_TUNNEL_OK` (p50 ≈ 906 ms) → clean process-tree teardown, no orphans |

## What was implemented

- **`core/platform/`** — the single platform abstraction: canonical detection
  (`windows-amd64`, `linux-amd64`, …), executable naming/resolution, process
  lifecycle, safe archive extraction, temp paths, POSIX-only permission
  handling. No platform logic lives anywhere else.
- **Per-platform core manifests** in `config/testing.yaml` — every core pins
  official `linux-amd64` and `windows-amd64` artifacts with exact SHA-256
  (Windows digests were computed from the official release archives and each
  binary was executed before pinning). A core without an artifact for the
  running platform is reported `unavailable` (fail closed — no insecure
  fallback), and its client feed is not published from that platform.
- **Windows process lifecycle** — cores spawn with
  `CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW`; teardown terminates the
  whole core tree (`taskkill /T`, force-kill fallback). POSIX keeps the
  existing process-group SIGTERM→SIGKILL semantics.
- **LF-stable writers** — every published/state artifact is written with
  pinned `\n` newlines so files are byte-identical across platforms
  (this fixed real CRLF corruption of base64 feed pairs on Windows).
- **CLI** — `status` (feed freshness + staleness warning) and `diagnose`
  (stage-by-stage diagnosis of one config, credentials always masked).

## Windows Quick Start (PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"

auto-subscription-engine --help
auto-subscription-engine cores-install          # installs pinned Windows cores
auto-subscription-engine status --public-dir public
auto-subscription-engine diagnose "<config-uri>" --runtime
```

The real publish pipeline (discovery → verification → scoring → feeds →
publish) runs exactly as documented in the README; on Windows every stage
uses the same code paths as Linux.

## Known limitations

- The hourly verification pipeline in GitHub Actions runs on `ubuntu-latest`
  (Linux). Windows verification runs locally or in `windows-ci.yml`.
- Runtime verification proves a tunnel works from the machine that ran it.
  Reachability from Iranian ISPs is a separate question — see
  **Evidence boundaries** in the README and the operator-probe workflow.
- `hiddify-core` ships no `hiddify-core.exe` at v4.1.0; the Windows artifact
  is `HiddifyCli.exe` + its pinned DLLs (all three files checksum-pinned).
