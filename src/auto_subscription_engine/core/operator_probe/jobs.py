"""Build bounded, expiring operator probe jobs from share URIs."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..protocols.registry import parse_uri
from ..models.fingerprint import normalize_config
from ..utils.identity import config_safe_id
from ..network import is_ip_literal
from .envelope import sign_payload
from .models import ProbeCandidate, ProbeJob


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def read_candidate_uris(path: Path) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        uri = line.strip()
        if not uri or "://" not in uri or uri in seen:
            continue
        try:
            parse_uri(uri)
        except Exception:  # noqa: BLE001 - invalid public candidate is skipped
            continue
        seen.add(uri)
        values.append(uri)
    return values


def build_probe_job(
    uris: list[str],
    *,
    operator_profile: str,
    ttl_minutes: int,
    limit: int,
    now: datetime | None = None,
    job_id: str | None = None,
) -> ProbeJob:
    now = now or _utc_now()
    candidates: list[ProbeCandidate] = []
    seen: set[str] = set()
    for uri in uris:
        if len(candidates) >= max(1, int(limit)):
            break
        try:
            config = normalize_config(parse_uri(uri))
        except Exception:  # noqa: BLE001
            continue
        if config.fingerprint in seen:
            continue
        seen.add(config.fingerprint)
        candidates.append(
            ProbeCandidate(
                safe_id=config_safe_id(config),
                fingerprint=config.fingerprint,
                uri=uri,
                protocol=config.protocol,
                direct_ip=is_ip_literal(config.host or ""),
            )
        )
    return ProbeJob(
        schema_version=1,
        job_id=job_id or secrets.token_hex(16),
        operator_profile=operator_profile,
        created_at=_iso(now),
        expires_at=_iso(now + timedelta(minutes=max(1, int(ttl_minutes)))),
        candidates=tuple(candidates),
    )


def write_signed_probe_job(job: ProbeJob, path: Path, *, key_id: str, secret: str) -> None:
    envelope = sign_payload(job.to_dict(), kind="probe_job", key_id=key_id, secret=secret)
    output = Path(path)
    output.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output.chmod(0o600)
