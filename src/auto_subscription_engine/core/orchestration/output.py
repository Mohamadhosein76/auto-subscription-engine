"""Output generation: subscription files and stats.

Determinism: the two subscription files contain only the sorted final
URIs — no timestamps — so unchanged input data always produces a
byte-identical output. The volatile ``generated_at`` timestamp lives
only in ``stats.json`` (see the README section on determinism).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from ..models import ParsedConfig


def write_outputs(
    configs: Sequence[ParsedConfig],
    stats: Mapping[str, object],
    output_dir: Path,
) -> None:
    """Write subscription.txt, subscription_base64.txt and stats.json."""
    output_dir.mkdir(parents=True, exist_ok=True)

    uris = [config.original_uri for config in configs]
    body = "\n".join(uris) + ("\n" if uris else "")

    (output_dir / "subscription.txt").write_text(body, encoding="utf-8")

    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    (output_dir / "subscription_base64.txt").write_text(encoded + "\n", encoding="ascii")

    stats_text = json.dumps(stats, indent=2, ensure_ascii=False)
    (output_dir / "stats.json").write_text(stats_text + "\n", encoding="utf-8")
