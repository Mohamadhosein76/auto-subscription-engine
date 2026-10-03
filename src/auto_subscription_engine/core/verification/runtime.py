"""Multi-core runtime verification.

A node is considered LIVE when at least one *compatible, pinned* core carries
the required application traffic.  This prevents sing-box from becoming an
accidental protocol gate (for example VLESS/XHTTP can be proven by Xray or
Mihomo while TUIC can be proven by sing-box/Hiddify/Mihomo).
"""
from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..utils.redaction import node_log
from ..utils.identity import describe_node
from ..clients.runtime import CoreRuntimeManager, RuntimeCoreError
from .http import fetch_through_proxy
from .models import EndpointPreflightResult, RuntimeVerificationResult, jitter, median, percentile
from .policy import VerificationPolicy

logger = logging.getLogger(__name__)


class CoreRuntimeRunner:
    """Verify one node with the first compatible core that truly passes.

    ``core_path`` is kept as a compatibility constructor for existing callers
    and means ``{"singbox": core_path}``.  Stage 7 callers should pass
    ``core_paths`` so features outside sing-box's capability set are not
    discarded before client-specific validation.
    """

    def __init__(
        self,
        core_path: Path | None = None,
        *,
        core_paths: dict[str, Path] | None = None,
        policy: VerificationPolicy,
        workdir_root: Path | None = None,
        preferred_cores: Sequence[str] = ("singbox", "xray", "hiddify", "mihomo"),
    ) -> None:
        paths = dict(core_paths or {})
        if core_path is not None:
            paths.setdefault("singbox", Path(core_path))
        self.policy = policy
        self.preferred_cores = tuple(preferred_cores)
        self.manager = CoreRuntimeManager(
            paths,
            startup_timeout=policy.startup_timeout_seconds,
            workdir_root=workdir_root,
        )

    def probe_node(
        self,
        config,
        *,
        server_override: str | None = None,
        mode: str = "native",
    ) -> RuntimeVerificationResult:
        cores = self.manager.candidate_cores(config, preferred=self.preferred_cores)
        if not cores:
            result = self._new_result(config, mode=mode, server_override=server_override)
            result.failure_reason = "no_compatible_runtime_core"
            return result

        failures: list[str] = []
        last: RuntimeVerificationResult | None = None
        for core in cores:
            result = self._new_result(config, mode=mode, server_override=server_override)
            result.attempted_cores = list(cores[: cores.index(core) + 1])
            try:
                session = self.manager.open(core, config, server_override=server_override)
            except RuntimeCoreError as exc:
                failures.append(f"{core}:{exc.category}")
                result.failure_reason = exc.category
                last = result
                continue

            result.core_started = True
            result.runtime_core = core
            try:
                for round_index in range(self.policy.repetitions):
                    for target in self.policy.targets:
                        result.probes.append(
                            fetch_through_proxy(
                                "127.0.0.1",
                                session.port,
                                target,
                                timeout=self.policy.http_timeout_seconds,
                                round_index=round_index,
                                max_body_bytes=self.policy.max_body_bytes,
                            )
                        )
                self._finalize(result)
            except Exception as exc:  # noqa: BLE001
                result.failure_reason = f"internal_error:{type(exc).__name__}"
            finally:
                session.close()

            if result.passed:
                logger.info(
                    "%s VERIFIED via %s (%s, %d successes, p50 %.0f ms)",
                    describe_node(config),
                    core,
                    mode,
                    result.success_count,
                    result.proxy_latency_ms or -1,
                )
                return result
            failures.append(f"{core}:{result.failure_reason or 'runtime_failed'}")
            last = result

        if last is None:
            last = self._new_result(config, mode=mode, server_override=server_override)
        last.attempted_cores = list(cores)
        last.runtime_core = None
        # Preserve Stage-5 single-core failure categories exactly.  Multi-core
        # runs add the attempted-core context so diagnostics remain actionable.
        if len(cores) > 1:
            last.failure_reason = "all_compatible_cores_failed:" + ",".join(failures)
        node_log(logger, logging.DEBUG, config, last.failure_reason or "runtime_failed")
        return last

    def cleanup(self) -> None:
        self.manager.cleanup()

    def _new_result(self, config, *, mode: str, server_override: str | None) -> RuntimeVerificationResult:
        return RuntimeVerificationResult(
            config=config,
            mode=mode,
            server_override=server_override,
            repetitions=self.policy.repetitions,
            min_success_ratio=self.policy.min_success_ratio,
            min_success_count=self.policy.min_success_count,
            min_round_success_ratio=self.policy.min_round_success_ratio,
        )

    def _finalize(self, result: RuntimeVerificationResult) -> None:
        required = [probe for probe in result.probes if probe.required]
        passed = [probe for probe in required if probe.ok]
        result.success_count = len(passed)
        result.success_ratio = len(passed) / len(required) if required else 0.0
        for round_index in range(self.policy.repetitions):
            round_required = [probe for probe in required if probe.round_index == round_index]
            round_passed = [probe for probe in round_required if probe.ok]
            result.round_success_ratios.append(
                len(round_passed) / len(round_required) if round_required else 0.0
            )
        latencies = [p.latency_ms for p in passed if p.latency_ms is not None]
        result.proxy_latency_ms = median(latencies)
        result.latency_p95_ms = percentile(latencies, 0.95)
        result.jitter_ms = jitter(latencies)
        if not result.passed:
            reasons = Counter(p.failure_reason or "unknown" for p in required if not p.ok)
            detail = ",".join(f"{k}={v}" for k, v in sorted(reasons.items()))
            result.failure_reason = f"runtime_quorum_failed:{detail or 'insufficient_success'}"


def run_runtime_stage(
    candidates: Sequence[EndpointPreflightResult],
    runner: CoreRuntimeRunner,
    *,
    concurrency: int,
    soft_deadline_seconds: float | None = None,
) -> tuple[list[RuntimeVerificationResult], int]:
    import time

    concurrency = max(1, int(concurrency))
    deadline = time.monotonic() + soft_deadline_seconds if soft_deadline_seconds is not None else None

    def worker(item: EndpointPreflightResult) -> RuntimeVerificationResult | None:
        if deadline is not None and time.monotonic() >= deadline:
            return None
        return runner.probe_node(item.config, mode="native")

    results: list[RuntimeVerificationResult] = []
    not_tested = 0
    try:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(worker, item) for item in candidates]
            for future in as_completed(futures):
                try:
                    outcome = future.result()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("runtime stage internal error: %s", type(exc).__name__)
                    outcome = None
                if outcome is None:
                    not_tested += 1
                else:
                    results.append(outcome)
    finally:
        runner.cleanup()
    results.sort(key=lambda result: result.config.fingerprint)
    return results, not_tested
