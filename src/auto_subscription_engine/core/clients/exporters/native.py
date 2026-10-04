"""Native, client-specific artifact writers.

Writers are deliberately dumb about selection: the compatibility engine hands
only runtime-proven configs to them.  Their job is faithful serialization and
atomic-ish file replacement inside the staging output tree.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import yaml

from ...utils.identity import config_safe_id
from ..builders.mihomo import build_mihomo_proxy
from ..builders.singbox import UnsupportedNodeError, build_outbound
from ..registry import CLIENTS, PLANNED_CLIENTS


def write_uri_feed(path: Path, uris: list[str]) -> None:
    path = Path(path)
    body = "\n".join(uris) + ("\n" if uris else "")
    path.write_text(body, encoding="utf-8", newline="\n")
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    path.with_name(path.stem + "_base64.txt").write_text(encoded + "\n", encoding="ascii", newline="\n")


def write_mihomo_configs(path: Path, configs: list) -> int:
    proxies: list[dict] = []
    for config in configs:
        try:
            sid = config_safe_id(config)
            proxy = build_mihomo_proxy(
                config,
                resolved_ip=(config.host if _is_ip(config.host or "") else None),
                name=f"ase-{sid[:13]}",
            )
        except UnsupportedNodeError:
            continue
        proxies.append(proxy)
    payload = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "unified-delay": True,
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": [p["name"] for p in proxies]}
        ],
        "rules": ["MATCH,PROXY"],
    }
    Path(path).write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8", newline="\n"
    )
    return len(proxies)


def write_mihomo_yaml(path: Path, evaluations: list[dict]) -> int:
    configs = [item.get("config") for item in evaluations if item.get("config") is not None]
    return write_mihomo_configs(path, configs)


def write_singbox_configs(path: Path, configs: list) -> int:
    outbounds: list[dict] = []
    for config in configs:
        try:
            outbound = build_outbound(config, resolved_ip=(config.host if _is_ip(config.host or "") else None))
        except UnsupportedNodeError:
            continue
        outbound = dict(outbound)
        outbound["tag"] = f"ase-{config_safe_id(config)[:13]}"
        outbounds.append(outbound)
    payload = {"outbounds": outbounds}
    Path(path).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    return len(outbounds)


def write_singbox_json(path: Path, evaluations: list[dict]) -> int:
    configs = [item.get("config") for item in evaluations if item.get("config") is not None]
    return write_singbox_configs(path, configs)


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def write_client_manifest(path: Path, *, feed_counts: dict[str, int], core_statuses: dict[str, str]) -> None:
    clients = []
    for key, spec in CLIENTS.items():
        clients.append({
            "client": key,
            "core": spec.core,
            "artifact": spec.artifact,
            "format": spec.format,
            "mapped_core_runtime_verified": spec.runtime_verified,
            "gui_import_verified": False,
            "core_status": core_statuses.get(spec.core, "unknown"),
            "count": int(feed_counts.get(key, 0)),
        })
    payload = {
        "schema_version": 1,
        "clients": clients,
        "planned_not_published": sorted(PLANNED_CLIENTS),
        "policy": (
            "a client feed is published only when its serializer exists and its mapped core "
            "is runtime-validated; GUI import is not claimed by CI and planned clients are "
            "never inferred from URI importability"
        ),
    }
    Path(path).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
