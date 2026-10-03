from __future__ import annotations

import json
from pathlib import Path

from auto_subscription_engine.core.clients.exporters.native import write_client_manifest
from auto_subscription_engine.core.clients.registry import CLIENTS, PLANNED_CLIENTS


def test_manifest_is_registry_derived_and_planned_clients_are_not_publishable(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    write_client_manifest(
        path,
        feed_counts={key: index for index, key in enumerate(CLIENTS, start=1)},
        core_statuses={spec.core: "available" for spec in CLIENTS.values()},
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = {row["client"]: row for row in payload["clients"]}
    assert set(rows) == set(CLIENTS)
    assert set(payload["planned_not_published"]) == set(PLANNED_CLIENTS)
    for key, spec in CLIENTS.items():
        assert rows[key]["core"] == spec.core
        assert rows[key]["artifact"] == spec.artifact
        assert rows[key]["format"] == spec.format
