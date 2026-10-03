# Stage 7 — Multi-Client Engine

Stage 7 removes the old split client/core implementation and introduces one
central client subsystem. A node is no longer forced through sing-box before it
can reach a client-specific compatibility test. Runtime truth is capability
aware: a node may prove itself with any installed, checksum-verified core that
actually supports its protocol/transport.

## Central source tree

All client/core logic now lives under:

```text
src/auto_subscription_engine/core/clients/
├── __init__.py
├── registry.py             # authoritative client/core capability registry
├── runtime.py              # single build/write/spawn/wait/kill lifecycle
├── install.py              # one checksum-verified installer for all cores
├── builders/
│   ├── adapters.py
│   ├── singbox.py
│   ├── xray.py
│   ├── hiddify.py
│   └── mihomo.py
├── compatibility/
│   ├── audit.py
│   ├── classify.py
│   ├── engine.py
│   ├── matrix.py
│   ├── runner.py
│   ├── score.py
│   └── verify.py
└── exporters/
    └── native.py
```

The replaced package-root implementations were deleted:

- `compat/`
- `singbox.py`
- `cores.py`

Architecture tests fail if those paths or their old absolute imports return.

## Core registry

The registry separates three concepts that had previously been mixed:

1. **core executable** — what is actually runtime-tested;
2. **client family** — which application family receives a feed;
3. **artifact format** — URI list, native sing-box JSON or Mihomo YAML.

Current mappings:

| Client/feed | Runtime core | Artifact |
|---|---|---|
| v2rayNG | Xray-core | `clients/v2rayng.txt` |
| Hiddify | Hiddify-Core | `clients/hiddify.txt` |
| NekoBox | sing-box | `clients/nekobox.txt` |
| sing-box | sing-box | `clients/singbox.json` |
| Mihomo/Clash.Meta | Mihomo | `clients/mihomo.yaml` |

`Shadowrocket`, `Stash`, `Loon`, `Surge` and `Quantumult X` are explicitly
recorded as **planned, not published**. Merely being able to parse a URI is not
accepted as proof that a client is supported.

The generated `clients/manifest.json` records the mapping and evidence boundary.
It states that mapped-core runtime evidence exists; it deliberately does **not**
claim GUI/mobile import validation from Linux CI.

## Multi-core initial runtime verification

Stage 5 used to be effectively gated by one core. Stage 7 changes the initial
runtime verifier to select the first compatible installed core from:

```text
sing-box -> Xray -> Hiddify-Core -> Mihomo
```

The order is deterministic, but unsupported cores are skipped by the capability
registry before process startup.

This fixes an important false-negative class:

- VLESS/XHTTP is not sent to sing-box/Hiddify when their pinned capability does
  not support it; Xray or Mihomo can prove the node LIVE.
- TUIC is not sent to Xray; sing-box, Hiddify-Core or Mihomo can prove it LIVE.

`live_nodes.json` records both `runtime_core` and `attempted_cores` so downstream
Security/Compatibility stages know what actually produced the evidence.

## Shared core lifecycle

Verification, Security and Compatibility no longer own separate copies of:

```text
build config -> write 0600 file -> spawn core -> wait for local proxy
-> use tunnel -> kill process -> remove temp directory
```

That lifecycle is centralized in `core/clients/runtime.py`.

Compatibility keeps richer per-target diagnostics, but process lifecycle and
cleanup are delegated to the central manager. Its fake-core tests exercise the
same lifecycle hook used by production adapters.

## TUIC

Stage 2 could parse TUIC but intentionally did not enable it in the live
pipeline. Stage 7 completes the runtime adapters.

Native mappings now exist for:

- sing-box / Hiddify-Core JSON;
- Mihomo YAML;
- client URI feeds where the Stage 2 serializer can preserve the share link.

Important fields retained include UUID, password, SNI, ALPN, congestion control,
UDP relay mode, explicit insecure setting and reduced-RTT/0-RTT options when
present.

The registry keeps Xray/v2rayNG TUIC support false instead of manufacturing a
configuration that Xray cannot run.

## XHTTP

XHTTP is now a per-core capability, not a global parser refusal.

For VLESS/XHTTP:

- Xray: supported;
- Mihomo: supported with `network: xhttp` + `xhttp-opts`;
- sing-box: unsupported in this pinned capability profile;
- Hiddify-Core: unsupported in this pinned capability profile.

There is no fallback that silently rewrites XHTTP to TCP/WS. A test locks this
behavior and another runtime test proves the Stage 5 verifier can route an
XHTTP candidate directly to Xray without trying sing-box first.

## Native artifacts

Stage 7 adds two new generated artifacts:

- `clients/singbox.json` — native sing-box outbound JSON;
- `clients/manifest.json` — client/core/format/evidence manifest.

Existing user-facing paths remain unchanged:

- `clients/v2rayng.txt`
- `clients/hiddify.txt`
- `clients/nekobox.txt`
- `clients/mihomo.yaml`
- `clients/universal.txt`

The compatibility verifier now checks the native sing-box JSON and manifest in
addition to URI/Base64 feeds and Mihomo YAML. Planned clients must not have
artifacts.

## Security stage

The Security tunnel probe no longer launches sing-box unconditionally. It uses
the same central runtime manager and prefers the `runtime_core` that already
proved the node LIVE. If needed it can fall through to another compatible core.

This prevents Security from reintroducing the exact capability gate that the
multi-core live verifier removed.

## Core installation and CLI

`core/clients/install.py` owns one archive/checksum installer for all four cores.
`cores-install` attempts every pinned core and only fails when **none** can be
installed; a sing-box failure alone no longer aborts an otherwise usable
multi-core run.

The main runtime/security/compatibility commands now use one core directory:

```text
--core-dir .core-bin
```

instead of passing different binaries through separate command-line switches.

## What Stage 7 does not claim

Stage 7 proves:

- native config construction for mapped cores;
- real core-process runtime compatibility when those binaries run in CI;
- feed serialization and offline artifact validation.

It does not claim that a Linux CI job has clicked the import UI of every Android
or iOS application. The manifest states this boundary explicitly. Stage 8 adds
network/operator probe infrastructure; client/device-specific probes can build on
that same evidence model rather than faking GUI validation here.

## Test coverage added/updated

Stage 7 tests cover:

- registry client/core mappings;
- planned-client non-publication;
- XHTTP capability split;
- TUIC capability split and native mappings;
- multi-core runtime routing of XHTTP to Xray;
- central core lifecycle use by Compatibility;
- native sing-box JSON generation;
- client manifest generation/verification;
- all four compatibility cores in the intersection;
- central-tree guards proving deleted legacy modules stay deleted;
- updated Stage 5 semantics after moving process lifecycle into the client core.
## Completion verification

Final Stage 7 verification before commit:

- full regression suite: **660 passed, 0 failed**;
- Python compileall: **PASS**;
- config/workflow YAML parse: **PASS**;
- existing `public/` publish verification: **PASS**;
- legacy Stage 7 import/path guard: **PASS**;
- Stage 6 -> Stage 7 structural fixture regression: `subscription.txt` and
  `subscription_base64.txt` are **byte-identical**.

Stage 7 intentionally does not claim Android/iOS GUI import validation. Its
evidence boundary is native serialization + mapped core runtime validation;
operator/device evidence is a later probe stage.
