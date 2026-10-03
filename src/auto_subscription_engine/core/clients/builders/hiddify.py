"""Hiddify-Core config builder (Hiddify app family, spec item 5).

Hiddify-Core is the official Hiddify core — a sing-box fork (the binary
reports ``hiddify-sing-box version``). Its per-node config format is the
sing-box JSON schema, so the builder reuses the existing sing-box
outbound mapping (which the live pipeline already validates against the
pinned sing-box) and wraps it in a mixed-inbound config. Differences
from plain sing-box are handled explicitly:

- the binary CLI is ``<hiddify-core> run -c <file>`` like sing-box;
- hysteria2 IS supported (unlike Xray) so Hiddify feeds can carry it;
- the config schema targets the pinned Hiddify-Core version's sing-box
  lineage (1.13.x) — only fields valid there are emitted.
"""

from __future__ import annotations

from ...models import ParsedConfig
from .singbox import build_outbound, build_node_config


def build_hiddify_config(
    config: ParsedConfig,
    *,
    listen_port: int,
    resolved_ip: str | None = None,
) -> dict:
    """Build a full Hiddify-Core (sing-box schema) config for one node.

    Raises :class:`UnsupportedNodeError` when the node uses a feature the
    Hiddify core cannot run (the underlying sing-box mapping decides).
    """
    # Reuse the sing-box per-node config: identical JSON schema, identical
    # mixed inbound + single outbound + final route shape.
    return build_node_config(config, listen_port=listen_port, resolved_ip=resolved_ip)


def build_hiddify_outbound(config: ParsedConfig, *, resolved_ip: str | None = None) -> dict:
    """Build only the outbound (kept for the capability matrix tests)."""
    return build_outbound(config, resolved_ip)
