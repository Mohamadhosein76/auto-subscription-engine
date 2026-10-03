"""Core adapters: config serialization, argv and port access per core."""

from __future__ import annotations

import json
import os
from pathlib import Path

import yaml

from .singbox import UnsupportedNodeError, build_node_config
from ..compatibility.classify import classify_network
from ..compatibility.matrix import NodeFeatures, capabilities_for, universal_eligible
from ..compatibility.audit import node_features, unmapped_features  # noqa: F401 (re-export)
from .xray import build_xray_config
from .hiddify import build_hiddify_config
from .mihomo import build_mihomo_config

# -- writers (0600 config files, credentials never in argv) -----------------


def write_json_config(config: dict, workdir: Path) -> Path:
    path = Path(workdir) / "config.json"
    path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def write_yaml_config(config: dict, workdir: Path) -> Path:
    path = Path(workdir) / "config.yaml"
    path.write_text(
        yaml.safe_dump(config, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return path


# -- argv builders (config via file; secrets never on the command line) -----

def singbox_argv(binary_path: Path, config_path: Path, workdir: Path) -> list[str]:
    return [str(binary_path), "run", "-c", str(config_path)]


def xray_argv(binary_path: Path, config_path: Path, workdir: Path) -> list[str]:
    return [str(binary_path), "run", "-c", str(config_path)]


def hiddify_argv(binary_path: Path, config_path: Path, workdir: Path) -> list[str]:
    # hiddify-core wraps sing-box as the "srun" subcommand; -D keeps its
    # runtime state inside the per-test temp dir (auto-cleaned).
    return [str(binary_path), "srun", "-c", str(config_path), "-D", str(workdir), "--disable-color"]


def mihomo_argv(binary_path: Path, config_path: Path, workdir: Path) -> list[str]:
    return [str(binary_path), "-f", str(config_path), "-d", str(workdir)]


# -- port getters ------------------------------------------------------------

def inbounds_port(config: dict) -> int:
    return int(config["inbounds"][0]["listen_port"])


def xray_inbound_port(config: dict) -> int:
    # Xray HTTP inbound uses the "port" field (not sing-box's listen_port).
    return int(config["inbounds"][0]["port"])


def mixed_port(config: dict) -> int:
    return int(config["mixed-port"])


# -- builders table -----------------------------------------------------------

BUILDERS = {
    "singbox": (build_node_config, write_json_config, singbox_argv, inbounds_port),
    "xray": (build_xray_config, write_json_config, xray_argv, xray_inbound_port),
    "hiddify": (build_hiddify_config, write_json_config, hiddify_argv, inbounds_port),
    "mihomo": (build_mihomo_config, write_yaml_config, mihomo_argv, mixed_port),
}


def node_support_summary(config) -> dict:
    """Matrix verdicts + audit flags for one parsed config (metadata only)."""
    features: NodeFeatures = node_features(config)
    caps = capabilities_for(features)
    profile = classify_network(config)
    return {
        "features": features,
        "capabilities": caps,
        "universal_eligible": universal_eligible(features),
        "unsupported_features": unmapped_features(config),
        "profile": profile,
    }
