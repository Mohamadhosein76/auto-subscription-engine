"""Stage 5 verification policy and config parsing."""
from __future__ import annotations

from dataclasses import dataclass, field
import math


@dataclass(frozen=True)
class VerificationTarget:
    url: str
    expect_statuses: tuple[int, ...] = (200, 204)
    expect_substring: str | None = None
    kind: str = "egress"
    required: bool = True


@dataclass(frozen=True)
class VerificationPolicy:
    connect_timeout_seconds: float = 3.0
    preflight_concurrency: int = 200
    max_addresses_per_node: int = 6
    runtime_concurrency: int = 10
    startup_timeout_seconds: float = 5.0
    http_timeout_seconds: float = 8.0
    repetitions: int = 2
    min_success_ratio: float = 2.0 / 3.0
    min_success_count: int = 4
    min_round_success_ratio: float = 0.5
    soft_deadline_seconds: float = 600.0
    max_body_bytes: int = 65536
    targets: tuple[VerificationTarget, ...] = field(default_factory=tuple)

    @classmethod
    def from_mapping(cls, raw: dict | None) -> "VerificationPolicy":
        raw = raw or {}
        targets: list[VerificationTarget] = []
        for entry in raw.get("targets", []) or []:
            if isinstance(entry, str):
                targets.append(VerificationTarget(url=entry))
                continue
            if not isinstance(entry, dict) or not entry.get("url"):
                continue
            targets.append(
                VerificationTarget(
                    url=str(entry["url"]),
                    expect_statuses=tuple(int(s) for s in entry.get("expect_status", [200, 204])),
                    expect_substring=(
                        str(entry["expect_substring"])
                        if entry.get("expect_substring") is not None
                        else None
                    ),
                    kind=str(entry.get("kind", "egress")),
                    required=bool(entry.get("required", True)),
                )
            )
        if not targets:
            targets = [
                VerificationTarget("https://www.gstatic.com/generate_204", (200, 204)),
                VerificationTarget(
                    "https://www.msftconnecttest.com/connecttest.txt", (200,), "Microsoft"
                ),
                VerificationTarget("https://example.com/", (200,), "Example Domain"),
            ]
        repetitions = max(1, int(raw.get("repetitions", 2)))
        min_success_ratio = float(raw.get("min_success_ratio", 2.0 / 3.0))
        required_per_round = sum(1 for target in targets if target.required)
        derived_min_count = max(1, math.ceil(required_per_round * repetitions * min_success_ratio))
        policy = cls(
            connect_timeout_seconds=float(raw.get("connect_timeout_seconds", 3.0)),
            preflight_concurrency=max(1, int(raw.get("preflight_concurrency", 200))),
            max_addresses_per_node=max(1, int(raw.get("max_addresses_per_node", 6))),
            runtime_concurrency=max(1, int(raw.get("runtime_concurrency", 10))),
            startup_timeout_seconds=float(raw.get("startup_timeout_seconds", 5.0)),
            http_timeout_seconds=float(raw.get("http_timeout_seconds", 8.0)),
            repetitions=repetitions,
            min_success_ratio=min_success_ratio,
            min_success_count=max(1, int(raw.get("min_success_count", derived_min_count))),
            min_round_success_ratio=float(raw.get("min_round_success_ratio", 0.5)),
            soft_deadline_seconds=float(raw.get("soft_deadline_seconds", 600.0)),
            max_body_bytes=max(1024, int(raw.get("max_body_bytes", 65536))),
            targets=tuple(targets),
        )
        policy.validate()
        return policy

    def validate(self) -> None:
        if not self.targets:
            raise ValueError("verification.targets must contain at least one target")
        if not 0 < self.min_success_ratio <= 1:
            raise ValueError("verification.min_success_ratio must be in (0, 1]")
        if not 0 <= self.min_round_success_ratio <= 1:
            raise ValueError("verification.min_round_success_ratio must be in [0, 1]")
        required_per_round = sum(1 for target in self.targets if target.required)
        if required_per_round <= 0:
            raise ValueError("verification requires at least one required target")
        max_required = required_per_round * self.repetitions
        if self.min_success_count > max_required:
            raise ValueError(
                "verification.min_success_count exceeds required probes across repetitions"
            )
