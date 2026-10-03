"""Deep offline verification for Stage-10 feed outputs."""
from __future__ import annotations
import base64
import json
from pathlib import Path
import yaml
from ..utils.identity import config_safe_id
from ..models.fingerprint import normalize_config
from ..protocols import parse_uri


def verify_feed_outputs(output_dir: Path) -> list[str]:
    root = Path(output_dir)
    problems: list[str] = []
    required = [
        "feed_manifest.json", "clients/universal.txt", "clients/v2rayng.txt",
        "clients/hiddify.txt", "clients/nekobox.txt", "clients/singbox.json",
        "clients/mihomo.yaml", "profiles/recommended.txt", "profiles/secure.txt",
        "profiles/max-compat.txt", "networks/direct-ip.txt", "networks/ipv4.txt",
        "networks/ipv6.txt", "networks/mobile-safe.txt",
    ]
    for name in required:
        if not (root / name).is_file():
            problems.append(f"missing feed artifact: {name}")
    if problems:
        return problems

    for txt in sorted(list((root / "clients").glob("*.txt")) + list((root / "networks").glob("*.txt")) + list((root / "profiles").glob("*.txt")) + list((root / "operators").glob("*/*.txt"))):
        if txt.name.endswith("_base64.txt"):
            continue
        companion = txt.with_name(txt.stem + "_base64.txt")
        if not companion.is_file():
            problems.append(f"missing base64 companion: {txt.relative_to(root)}")
            continue
        try:
            decoded = base64.b64decode(companion.read_text(encoding="ascii").strip(), validate=True).decode("utf-8")
        except Exception:
            problems.append(f"invalid base64 companion: {companion.relative_to(root)}")
            continue
        if decoded != txt.read_text(encoding="utf-8"):
            problems.append(f"base64 mismatch: {txt.relative_to(root)}")

    try:
        nodes = json.loads((root / "live_nodes.json").read_text(encoding="utf-8"))
        manifest = json.loads((root / "feed_manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return problems + [f"feed metadata unreadable: {exc}"]
    meta = {str(x.get("safe_id")): x for x in nodes if isinstance(x, dict) and x.get("safe_id")}

    universal = _uris(root / "clients" / "universal.txt")
    main = _uris(root / "live_subscription.txt")
    if universal != main:
        problems.append("legacy live_subscription.txt does not equal clients/universal.txt")
    for uri in universal:
        sid = _safe_id(uri)
        if not sid or not bool((meta.get(sid) or {}).get("universal_compatible")):
            problems.append("universal feed contains a non-universal node")

    client_fields = {"v2rayng": "xray_compatible", "hiddify": "hiddify_compatible", "nekobox": "singbox_compatible"}
    for client, field in client_fields.items():
        for uri in _uris(root / "clients" / f"{client}.txt"):
            sid = _safe_id(uri)
            if not sid or (meta.get(sid) or {}).get(field) != "pass":
                problems.append(f"clients/{client}.txt contains a node without {field}=pass")

    for operator_dir in sorted((root / "operators").glob("*")):
        if not operator_dir.is_dir():
            continue
        operator = operator_dir.name
        for txt in operator_dir.glob("*.txt"):
            if txt.name.endswith("_base64.txt"):
                continue
            for uri in _uris(txt):
                sid = _safe_id(uri)
                dim = (((meta.get(sid) or {}).get("scores") or {}).get("operators") or {}).get(operator) or {}
                if dim.get("fresh") is not True or not isinstance(dim.get("score"), int):
                    problems.append(f"operators/{operator}/{txt.name} contains node without fresh operator evidence")

    try:
        sb = json.loads((root / "clients" / "singbox.json").read_text(encoding="utf-8"))
        if not isinstance(sb, dict) or not isinstance(sb.get("outbounds"), list):
            problems.append("clients/singbox.json missing outbounds")
    except Exception:
        problems.append("clients/singbox.json invalid JSON")
    try:
        mm = yaml.safe_load((root / "clients" / "mihomo.yaml").read_text(encoding="utf-8")) or {}
        if not isinstance(mm, dict) or not isinstance(mm.get("proxies"), list):
            problems.append("clients/mihomo.yaml missing proxies")
    except Exception:
        problems.append("clients/mihomo.yaml invalid YAML")

    if not isinstance(manifest, dict) or manifest.get("engine") != "score-aware-feed-v2":
        problems.append("feed_manifest.json has invalid engine/schema")
    return problems


def _uris(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def _safe_id(uri: str) -> str | None:
    try:
        return config_safe_id(normalize_config(parse_uri(uri)))
    except Exception:
        return None
