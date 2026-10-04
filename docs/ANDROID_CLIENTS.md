# Android Clients

ASE publishes Android-consumable subscription feeds. The engine itself does
not run on Android; Android is an **output** platform.

## Feed files (Android)

Base URL:
`https://raw.githubusercontent.com/Mohamadhosein76/auto-subscription-engine/main/public/`

| Client | File | Format | Runtime core evidence |
|---|---|---|---|
| v2rayNG | `platforms/android/v2rayng.txt` | URI list (+ `_base64.txt`) | Xray-core verified |
| Hiddify | `platforms/android/hiddify.txt` | URI list (+ `_base64.txt`) | Hiddify-Core verified |
| NekoBox | `platforms/android/nekobox.txt` | URI list (+ `_base64.txt`) | sing-box verified |
| sing-box | `platforms/android/singbox.json` | sing-box JSON | sing-box verified |
| Mihomo/Clash-compatible | `platforms/android/mihomo.yaml` | Clash/Mihomo YAML | Mihomo verified |

The mirrored files under `platforms/android/` are byte-identical to the
canonical artifacts under `clients/` — same serializer, same runtime-core
evidence, no new compatibility claims.

## Import method

1. Copy the feed URL for your client from the table above.
2. In the client: Subscriptions → Add subscription → paste URL → update.
3. Base64 variants exist for every `.txt` feed (`*_base64.txt`) for clients
   that require Base64 subscription bodies.

## Real-device observation (manual, recorded honestly)

```text
Platform:            Android
Client:              Hiddify (real device)
Observation:         most published configs showed failed/red state;
                     approximately 4 configs were usable at the time
Status:              manual_device_observation
```

This is a **manual** observation. It is NOT automated device measurement
and it is not fed into scoring. Automated device probing does not exist
yet; until it does, every platform manifest records
`device_validation: manual_observation_only`.

## CI runtime verification != Android GUI device validation

A node can pass server-side runtime verification (real tunneled HTTPS
through Hiddify-Core on the CI runner) and still fail on a specific
ISP/device/client combination. The dominant cause: verification runs from
GitHub datacenters, while device reachability depends on the local
network — direct-IP endpoints on non-standard ports are frequently
unreachable from Iranian ISPs, while CDN-fronted endpoints usually work.
Operator compatibility is a separate dimension and is only ever proven by
physical probes on that network.

## Evidence boundaries (important)

- `runtime_core_verified` means the pinned core that represents the client's
  engine (Xray-core for v2rayNG, Hiddify-Core for Hiddify, sing-box for
  NekoBox/sing-box, Mihomo for Clash-compatible clients) carried real
  application traffic through the tunnel **on the verification runner**.
- `device_validation_unknown` — ASE has NOT run these clients on any Android
  device. GUI import behavior, app versions and device-specific quirks are
  deliberately not claimed. Every platform manifest states this explicitly.
- Operator compatibility (`Works on MCI / Irancell / Rightel / Fixed`) is a
  separate dimension and requires fresh evidence from self-hosted physical
  probes on those networks. Nothing in this file constitutes operator
  evidence.

## Troubleshooting

- Feed not updating: check `status.json` (`last_successful_publish`) or run
  `auto-subscription-engine status`.
- Nodes listed but not connecting: the nodes are verified from the CI
  runner's network. Your local network may block the endpoints — run
  `auto-subscription-engine diagnose "<config-uri>"` to see exactly which
  stage fails (DNS / TCP / TLS / tunnel).
