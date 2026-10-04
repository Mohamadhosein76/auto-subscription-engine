"""Shared helpers for platform contract tests (unique module name to
avoid conftest shadowing across pytest's sys.path insertion)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "fake_cores"


def install_fake_core(tmp_path: Path, name: str) -> Path:
    """Platform-correct fake core launcher (shebang script vs .cmd shim)."""
    if os.name != "posix":
        source = FIXTURES / name
        target = tmp_path / (Path(name).stem + ".cmd")
        target.write_text(
            f'@"{sys.executable}" "{source}" %*' + "\r\n", encoding="utf-8"
        )
        return target
    target = tmp_path / name
    target.write_bytes((FIXTURES / name).read_bytes())
    target.chmod(0o755)
    return target


def _fake_builder(config, *, listen_port, resolved_ip=None):
    return {"inbounds": [{"listen_port": listen_port}], "protocol": config.protocol}


def _fake_json_writer(config, workdir):
    from auto_subscription_engine.core.platform.paths import set_owner_only_permissions

    path = Path(workdir) / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    set_owner_only_permissions(path)
    return path


def _fake_argv(binary, config_path, workdir):
    return [str(binary), "run", "-c", str(config_path)]


def _fake_port(config):
    return int(config["inbounds"][0]["listen_port"])
