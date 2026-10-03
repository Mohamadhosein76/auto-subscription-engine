# ASE Core — authoritative production source tree

All production business logic lives under this directory. The package root is intentionally limited to package/CLI entry points; Stage 12 removed the remaining root orchestration, security, network, output, identity and verification implementations rather than leaving compatibility shims.

```text
core/
├── models/          canonical proxy schema, validation, fingerprinting, dedup
├── protocols/       protocol parser registry and protocol-specific parsers
├── ingestion/       text/container ingestion and structured adapters
├── serialization/   canonical share-URI serialization
├── discovery/       source graph, fetch, intelligence and quarantine
├── network/         addresses, DNS history, geolocation and Static-IP Hunter
├── scheduling/      persistent adaptive work planning and backoff
├── verification/    preflight + repeated real-core application verification
├── clients/         pinned core registry/runtime, builders, exporters, compatibility
├── security/        reputation/ASN/DNS/TLS/content evidence and policy
├── operator_probe/  signed physical-network evidence + nested Go supervisor
├── scoring/         contextual multidimensional scores
├── feeds/           sole final feed-membership authority
├── hardening/       durable state, crash-safe publication and release gate
├── orchestration/   structural/live pipeline composition and output verification
└── utils/           safe identity/redaction/base64 helpers
```

Architecture and evidence boundaries are documented in `docs/ARCHITECTURE.md`; configuration in `docs/CONFIGURATION.md`.
