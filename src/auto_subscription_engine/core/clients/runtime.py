"""Shared lifecycle for all runtime-tested proxy cores.

Stage 7 removes three independent implementations of
``build -> write -> spawn -> wait -> kill``.  Verification, security and the
client-compatibility stage now use this one lifecycle primitive.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from ..utils.redaction import redact_stderr
from ..models import ParsedConfig
from ..platform import core_process_kwargs, is_posix, terminate_process_tree
from .builders.adapters import BUILDERS
from .builders.singbox import UnsupportedNodeError, allocate_port
from .compatibility.audit import node_features
from .compatibility.matrix import capabilities_for


class RuntimeCoreError(RuntimeError):
    def __init__(self, category: str, detail: str = "") -> None:
        super().__init__(category)
        self.category = category
        self.detail = detail


@dataclass
class RunningCore:
    core: str
    port: int
    process: subprocess.Popen
    workdir: Path
    manager: "CoreRuntimeManager"

    def close(self) -> None:
        self.manager.close(self)


class CoreRuntimeManager:
    """Start/stop any pinned core through the same safe lifecycle."""

    DEFAULT_ORDER = ("singbox", "xray", "hiddify", "mihomo")

    def __init__(
        self,
        core_paths: dict[str, Path],
        *,
        startup_timeout: float = 8.0,
        workdir_root: Path | None = None,
    ) -> None:
        self.core_paths = {
            key: Path(value)
            for key, value in core_paths.items()
            if value is not None and Path(value).is_file()
        }
        self.startup_timeout = float(startup_timeout)
        self.workdir_root = Path(workdir_root) if workdir_root else None
        self._sessions: list[RunningCore] = []

    def candidate_cores(
        self,
        config: ParsedConfig,
        *,
        preferred: tuple[str, ...] | list[str] | None = None,
    ) -> list[str]:
        caps = capabilities_for(node_features(config))
        order = tuple(preferred or self.DEFAULT_ORDER)
        return [
            core for core in order
            if core in self.core_paths
            and caps.get(core) is not None
            and caps[core].supported
            and core in BUILDERS
        ]

    def open(
        self,
        core: str,
        config: ParsedConfig,
        *,
        server_override: str | None = None,
    ) -> RunningCore:
        binary = self.core_paths.get(core)
        if binary is None:
            raise RuntimeCoreError("core_unavailable", core)
        adapter = BUILDERS.get(core)
        if adapter is None:
            raise RuntimeCoreError("core_adapter_missing", core)
        builder, writer, argv_builder, port_getter = adapter
        return self.open_with_adapter(
            core,
            binary,
            config,
            builder=builder,
            writer=writer,
            argv_builder=argv_builder,
            port_getter=port_getter,
            server_override=server_override,
        )

    def open_with_adapter(
        self,
        core: str,
        binary: Path,
        config: ParsedConfig,
        *,
        builder,
        writer,
        argv_builder,
        port_getter,
        server_override: str | None = None,
    ) -> RunningCore:
        """Open a core through the one shared lifecycle using an explicit adapter.

        The compatibility test harness uses this hook so its fake adapters exercise
        the exact same process/config/cleanup path as production cores.
        """
        try:
            node_config = builder(
                config,
                listen_port=allocate_port(),
                resolved_ip=server_override,
            )
        except UnsupportedNodeError as exc:
            raise RuntimeCoreError(f"config_unsupported:{exc.reason}", core) from exc
        except Exception as exc:  # noqa: BLE001
            raise RuntimeCoreError(f"config_build_failed:{type(exc).__name__}", core) from exc

        root = self.workdir_root or Path(tempfile.gettempdir())
        root.mkdir(parents=True, exist_ok=True)
        workdir = Path(tempfile.mkdtemp(prefix=f"ase-core-{core}-", dir=root))
        if is_posix():
            workdir.chmod(0o700)
        process: subprocess.Popen | None = None
        try:
            config_path = writer(node_config, workdir)
            argv = list(argv_builder(Path(binary), config_path, workdir))
            process = subprocess.Popen(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                # Each core runs detached in its own group/tree so cleanup
                # terminates helper/child processes spawned by that core.
                **core_process_kwargs(),
            )
            port = int(port_getter(node_config))
            if not self._wait_ready(port, process):
                detail = self._stderr_tail(process) if process.poll() is not None else ""
                category = "core_startup_failed" if process.poll() is not None else "core_startup_timeout"
                self._terminate_process(process)
                shutil.rmtree(workdir, ignore_errors=True)
                raise RuntimeCoreError(category, detail)
            session = RunningCore(core=core, port=port, process=process, workdir=workdir, manager=self)
            self._sessions.append(session)
            return session
        except RuntimeCoreError:
            raise
        except Exception as exc:  # noqa: BLE001
            if process is not None:
                self._terminate_process(process)
            shutil.rmtree(workdir, ignore_errors=True)
            raise RuntimeCoreError(f"core_launch_failed:{type(exc).__name__}", core) from exc

    def close(self, session: RunningCore) -> None:
        self._terminate_process(session.process)
        shutil.rmtree(session.workdir, ignore_errors=True)
        try:
            self._sessions.remove(session)
        except ValueError:
            pass

    def cleanup(self) -> None:
        for session in list(self._sessions):
            self.close(session)

    def _wait_ready(self, port: int, process: subprocess.Popen) -> bool:
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    @staticmethod
    def _stderr_tail(process: subprocess.Popen) -> str:
        try:
            _out, stderr = process.communicate(timeout=2)
            return redact_stderr(stderr or b"")[:300]
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _terminate_process(process: subprocess.Popen) -> None:
        """Terminate the complete core process tree, never leaving helpers behind."""
        terminate_process_tree(process)
