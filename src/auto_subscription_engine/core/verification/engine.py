"""Facade for endpoint preflight + multi-core runtime verification."""
from __future__ import annotations

from pathlib import Path

from .policy import VerificationPolicy
from .preflight import run_preflight_stage
from .runtime import CoreRuntimeRunner, run_runtime_stage


class VerificationEngine:
    def __init__(self, core_paths: dict[str, Path] | Path, policy: VerificationPolicy) -> None:
        if isinstance(core_paths, (str, Path)):
            self.core_paths = {"singbox": Path(core_paths)}
        else:
            self.core_paths = {key: Path(value) for key, value in core_paths.items()}
        self.policy = policy

    def preflight(self, configs):
        return run_preflight_stage(
            configs,
            timeout=self.policy.connect_timeout_seconds,
            concurrency=self.policy.preflight_concurrency,
            max_addresses=self.policy.max_addresses_per_node,
        )

    def runtime(self, candidates):
        runner = CoreRuntimeRunner(core_paths=self.core_paths, policy=self.policy)
        return run_runtime_stage(
            candidates,
            runner,
            concurrency=self.policy.runtime_concurrency,
            soft_deadline_seconds=self.policy.soft_deadline_seconds,
        )
