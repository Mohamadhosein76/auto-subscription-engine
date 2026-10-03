# Stage 2 — Canonical Model + Parser Engine v2

## Status

Complete on branch `ase-next/stage-2-canonical`.

## Goal

Create one centralized, extensible parsing/ingestion layer before adding discovery,
static-IP hunting, operator probes, or new runtime client adapters.

## Central source tree

All new Stage 2 implementation is located under:

`src/auto_subscription_engine/core/`

The previous parser/model modules remain only as compatibility shims. This avoids keeping
two independent implementations and lets existing production imports continue working.

## Canonical model

`CanonicalProxy` separates:

- endpoint (`host`, `port`)
- authentication fields
- transport settings
- TLS / Reality settings
- protocol-specific options
- source/origin metadata
- unmapped fields
- logical fingerprint

This is deliberately richer than the legacy `ParsedConfig` model while still allowing
loss-aware conversion between the two representations.

## URI protocol registry

Parser registry currently understands:

- VLESS
- VMess
- Trojan
- Shadowsocks / SIP002
- Hysteria2 (`hy2` alias)
- TUIC v5 share links

TUIC is **parse-enabled but live-gated**. It is not allowed into the legacy live pipeline
until Stage 7 adds verified runtime/client adapters. This prevents parsed support from being
mistaken for tested support.

The registry exposes an explicit registration function so future protocols such as AnyTLS,
ShadowTLS, Naive, Mieru, and others can be added without editing one giant dispatcher.

## Multi-format ingestion

The Stage 2 ingestion engine accepts:

- plain URI subscription lists
- Base64-wrapped URI subscriptions
- Base64-wrapped structured documents
- Clash / Mihomo YAML `proxies`
- Clash / Mihomo `proxy-providers` URL discovery
- sing-box JSON `outbounds`
- Xray JSON `outbounds`
- Hiddify import deeplink nested-subscription discovery

Nested URLs are returned but never fetched in Stage 2. Network discovery remains Stage 3.

## Structured protocol mappings

Structured adapters cover the Stage 2 canonical protocol set and preserve transport/security
information where available, including:

- WebSocket path / Host
- gRPC service name
- TLS SNI / ALPN
- Reality public key / short ID
- client fingerprint metadata
- Hysteria2 obfuscation
- Shadowsocks plugins
- TUIC UUID/password, congestion control, UDP relay mode, ALPN and SNI

Unknown or unmapped Clash fields are retained in `extra_fields` rather than silently dropped.

## Canonical share-link serialization

Canonical nodes can be serialized back to common share URIs for:

- VLESS
- VMess
- Trojan
- Shadowsocks
- Hysteria2
- TUIC

This makes structured-source ingestion useful to later publishing stages without tying the
canonical model to one input container.

## Fingerprints

Stage 2 adds canonical fingerprints computed from connection semantics, not the source
container or display name. Equivalent nodes arriving from different supported formats are
expected to deduplicate to the same logical identity.

## Backward compatibility

The legacy production path remains active and unchanged for Stage 2. A byte-for-byte regression
check using `tests/fixtures/mixed_subscription.txt` produced identical `subscription.txt` and
`subscription_base64.txt` outputs between Stage 1 and Stage 2.

## Verification snapshot

At Stage 2 completion:

- full pytest suite: **613 passed**
- Stage 2 tests: **16 passed**
- Python compileall: **PASS**
- `verify-publish --public-dir public`: **PASS**
- `git diff --check`: **PASS**
- legacy fixture output comparison: **BYTE IDENTICAL**

No discovery engine, static-IP hunting, operator probing, or new runtime compatibility claims
were added in this stage.


> **Stage 3 cleanup note:** the temporary Stage 2 compatibility shims described above were removed once all imports were migrated to the central `core/` tree.
